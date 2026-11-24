/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.dhcp6;

import static android.provider.DeviceConfig.NAMESPACE_CONNECTIVITY;

import static com.android.net.module.util.dhcp6.Dhcp6Packet.AddressAssignment;
import static com.android.net.module.util.dhcp6.Dhcp6Packet.IAID;
import static com.android.net.module.util.dhcp6.Dhcp6Packet.PrefixDelegation;
import static com.android.net.module.util.NetworkStackConstants.RFC7421_PREFIX_LENGTH;

import android.content.Context;
import android.net.ip.IpClient;
import android.os.Message;
import android.os.SystemClock;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.internal.util.HexDump;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;
import com.android.internal.util.WakeupMessage;
import com.android.net.module.util.DeviceConfigUtils;
import com.android.net.module.util.InterfaceParams;
import com.android.net.module.util.dhcp6.Dhcp6AdvertisePacket;
import com.android.net.module.util.dhcp6.Dhcp6Packet;
import com.android.net.module.util.dhcp6.Dhcp6ReplyPacket;
import com.android.net.module.util.structs.IaAddressOption;
import com.android.net.module.util.structs.IaPrefixOption;

import java.net.Inet6Address;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.function.IntSupplier;

/**
 * A DHCPv6 client.
 *
 * Supports IA_PD (prefix delegation) and IA_NA (non-temporary address assignment).
 *
 * @hide
 */
public class Dhcp6Client extends StateMachine {
    private static final String TAG = Dhcp6Client.class.getSimpleName();
    private static final boolean DBG = true;

    // Dhcp6Client shares the same handler with IpClient, define the base command range for
    // both public and private messages used in Dhcp6Client, to avoid commands overlap.
    // Public messages.
    private static final int PUBLIC_BASE = IpClient.DHCP6CLIENT_CMD_BASE;
    // Commands from controller to start/stop DHCPv6
    public static final int CMD_START_DHCP6 = PUBLIC_BASE + 1;
    public static final int CMD_STOP_DHCP6  = PUBLIC_BASE + 2;
    // Notification from DHCPv6 state machine post DHCPv6 discovery/renewal. Indicates
    // success/failure
    public static final int CMD_DHCP6_RESULT = PUBLIC_BASE + 3;
    // Commands from controller to force doing a DHCPv6 PD Rebind.
    public static final int CMD_REBIND_DHCP6 = PUBLIC_BASE + 4;
    // Notification from DHCPv6 state machine before quitting
    public static final int CMD_ON_QUIT = PUBLIC_BASE + 5;
    // Commands from controller to decline an address due to DAD conflict
    public static final int CMD_DECLINE_DHCP6 = PUBLIC_BASE + 6;
    // Commands from controller to confirm address after roaming
    public static final int CMD_CONFIRM_DHCP6 = PUBLIC_BASE + 7;

    // Message.arg1 arguments to CMD_DHCP6_RESULT notification
    public static final int DHCP6_PD_SUCCESS = 1;
    public static final int DHCP6_PD_PREFIX_EXPIRED = 2;
    public static final int DHCP6_NA_SUCCESS = 3;
    public static final int DHCP6_NA_ADDRESS_EXPIRED = 4;
    public static final int DHCP6_INFO_SUCCESS = 5;

    // Operational modes
    public static final int MODE_IA_PD = 1 << 0;
    public static final int MODE_IA_NA = 1 << 1;
    public static final int MODE_INFO_REQUEST = 1 << 2;
    public static final int MODE_DUAL = MODE_IA_PD | MODE_IA_NA;

    /**
     * Container holding DHCPv6 lease results (prefixes, addresses, DNS servers, domain list).
     */
    public static class Dhcp6Lease {
        @Nullable public final List<IaPrefixOption> ipos;
        @Nullable public final List<IaAddressOption> iaAddrs;
        @NonNull public final List<Inet6Address> dnsServers;
        @NonNull public final List<String> domainList;

        public Dhcp6Lease(@Nullable List<IaPrefixOption> ipos,
                @Nullable List<IaAddressOption> iaAddrs,
                @NonNull List<Inet6Address> dnsServers,
                @NonNull List<String> domainList) {
            this.ipos = ipos;
            this.iaAddrs = iaAddrs;
            this.dnsServers = dnsServers;
            this.domainList = domainList;
        }

        public boolean hasPrefixDelegation() {
            return ipos != null && !ipos.isEmpty();
        }

        public boolean hasAddressAssignment() {
            return iaAddrs != null && !iaAddrs.isEmpty();
        }

        @Override
        public String toString() {
            return "Dhcp6Lease{prefixes=" + ipos + ", addrs=" + iaAddrs
                    + ", dns=" + dnsServers + ", domains=" + domainList + "}";
        }
    }

    // Internal messages.
    private static final int PRIVATE_BASE        = IpClient.DHCP6CLIENT_CMD_BASE + 100;
    private static final int CMD_RECEIVED_PACKET = PRIVATE_BASE + 1;
    private static final int CMD_KICK            = PRIVATE_BASE + 2;
    private static final int CMD_DHCP6_PD_RENEW  = PRIVATE_BASE + 3;
    private static final int CMD_DHCP6_PD_REBIND = PRIVATE_BASE + 4;
    private static final int CMD_DHCP6_PD_EXPIRE = PRIVATE_BASE + 5;

    // Transmission and Retransmission parameters in milliseconds.
    private static final int SECONDS            = 1000;
    private static final int SOL_TIMEOUT        =    1 * SECONDS;
    private static final int SOL_MAX_RT         = 3600 * SECONDS;
    private static final int REQ_TIMEOUT        =    1 * SECONDS;
    private static final int REQ_MAX_RT         =   30 * SECONDS;
    private static final int REQ_MAX_RC         =   10;
    private static final int REN_TIMEOUT        =   10 * SECONDS;
    private static final int REN_MAX_RT         =  600 * SECONDS;
    private static final int REB_TIMEOUT        =   10 * SECONDS;
    private static final int REB_MAX_RT         =  600 * SECONDS;

    private int mSolMaxRtMs = SOL_MAX_RT;

    private int mMode = MODE_IA_PD;
    @Nullable private PrefixDelegation mAdvertisePd;
    @Nullable private PrefixDelegation mReplyPd;
    @Nullable private AddressAssignment mAdvertiseAa;
    @Nullable private AddressAssignment mReplyAa;
    @NonNull private final List<Inet6Address> mDnsServers = new ArrayList<>();
    @NonNull private final List<String> mDomainList = new ArrayList<>();
    @Nullable private byte[] mServerDuid;

    // State variables.
    @NonNull private final Dependencies mDependencies;
    @NonNull private final Context mContext;
    @NonNull private final Random mRandom;
    @NonNull private final StateMachine mController;
    @NonNull private final WakeupMessage mKickAlarm;
    @NonNull private final WakeupMessage mRenewAlarm;
    @NonNull private final WakeupMessage mRebindAlarm;
    @NonNull private final WakeupMessage mExpiryAlarm;
    @NonNull private final InterfaceParams mIface;
    @NonNull private final Dhcp6PacketDispatcher mDhcp6PacketDispatcher;
    @NonNull private final Dhcp6PacketDispatcher.MessageHandler mDhcp6MessageHandler;
    @NonNull private final byte[] mClientDuid;

    // States.
    private State mStoppedState = new StoppedState();
    private State mStartedState = new StartedState();
    private State mSolicitState = new SolicitState();
    private State mRequestState = new RequestState();
    private State mInfoRequestState = new InfoRequestState();
    private State mHaveLeaseState = new HaveLeaseState();
    private State mBoundState = new BoundState();
    private State mRenewState = new RenewState();
    private State mRebindState = new RebindState();

    /**
     * Encapsulates Dhcp6Client depencencies that's used for unit testing and
     * integration testing.
     */
    public static class Dependencies {
        /**
         * Read an integer DeviceConfig property.
         */
        public int getDeviceConfigPropertyInt(String name, int defaultValue) {
            return DeviceConfigUtils.getDeviceConfigPropertyInt(NAMESPACE_CONNECTIVITY, name,
                    defaultValue);
        }
    }

    private WakeupMessage makeWakeupMessage(String cmdName, int cmd) {
        cmdName = Dhcp6Client.class.getSimpleName() + "." + mIface.name + "." + cmdName;
        return new WakeupMessage(mContext, getHandler(), cmdName, cmd);
    }

    private Dhcp6Client(@NonNull final Context context, @NonNull final StateMachine controller,
            @NonNull final InterfaceParams iface, @NonNull final Dhcp6PacketDispatcher dispatcher,
            @NonNull final Dependencies deps) {
        super(TAG, controller.getHandler());

        mDependencies = deps;
        mContext = context;
        mController = controller;
        mIface = iface;
        mClientDuid = Dhcp6Packet.createClientDuid(iface.macAddr);
        mDhcp6PacketDispatcher = dispatcher;
        // It is safe to process stale DHCPv6 messages because they contain a transaction ID.
        // This ensures that even in the unlikely event of receiving an out-of-order message,
        // it can be handled correctly.
        mDhcp6MessageHandler = (packet, dst) -> sendMessage(CMD_RECEIVED_PACKET, packet);

        addState(mStoppedState);
        addState(mStartedState); {
            addState(mSolicitState, mStartedState);
            addState(mRequestState, mStartedState);
            addState(mInfoRequestState, mStartedState);
            addState(mHaveLeaseState, mStartedState); {
                addState(mBoundState, mHaveLeaseState);
                addState(mRenewState, mHaveLeaseState);
                addState(mRebindState, mHaveLeaseState);
            }
        }

        setInitialState(mStoppedState);

        mRandom = new Random();

        // Used to schedule packet retransmissions.
        mKickAlarm = makeWakeupMessage("KICK", CMD_KICK);
        // Used to schedule DHCP reacquisition.
        mRenewAlarm = makeWakeupMessage("RENEW", CMD_DHCP6_PD_RENEW);
        mRebindAlarm = makeWakeupMessage("REBIND", CMD_DHCP6_PD_REBIND);
        mExpiryAlarm = makeWakeupMessage("EXPIRY", CMD_DHCP6_PD_EXPIRE);
    }

    /**
     * Get current DHCPv6 operation mode.
     */
    public int getMode() {
        return mMode;
    }

    /**
     * Make a Dhcp6Client instance.
     */
    public static Dhcp6Client makeDhcp6Client(@NonNull final Context context,
            @NonNull final StateMachine controller, @NonNull final InterfaceParams ifParams,
            @NonNull final Dhcp6PacketDispatcher dispatcher,
            @NonNull final Dependencies deps) {
        final Dhcp6Client client = new Dhcp6Client(context, controller, ifParams, dispatcher, deps);
        client.start();
        return client;
    }

    /**
     * Quit the Dhcp6 StateMachine.
     *
     * @hide
     */
    public void doQuit() {
        Log.d(TAG, "doQuit");
        quit();
    }

    @Override
    protected void onQuitting() {
        Log.d(TAG, "onQuitting");
        mController.sendMessage(CMD_ON_QUIT);
    }

    /**
     * Retransmits packets per algorithm defined in RFC8415 section 15. Packet transmission is
     * triggered by CMD_KICK, which is sent by an AlarmManager alarm. Kicks are cancelled when
     * leaving the state.
     *
     * Concrete subclasses must initialize retransmission parameters and implement sendPacket,
     * which is called when the alarm fires and a packet needs to be transmitted, and receivePacket,
     * which is triggered by CMD_RECEIVED_PACKET sent by the receive thread.
     */
    abstract class MessageExchangeState extends State {
        private int mTransId = 0;
        private long mTransStartMs = 0;
        private long mMaxRetransTimeMs = 0;

        private long mRetransTimeout = -1;
        private int mRetransCount = 0;
        private final long mInitialDelayMs;
        private final long mInitialRetransTimeMs;
        private final int mMaxRetransCount;
        private final IntSupplier mMaxRetransTimeSupplier;

        MessageExchangeState(final int delay, final int irt, final int mrc, final IntSupplier mrt) {
            mInitialDelayMs = delay;
            mInitialRetransTimeMs = irt;
            mMaxRetransCount = mrc;
            mMaxRetransTimeSupplier = mrt;
        }

        @Override
        public void enter() {
            super.enter();
            mMaxRetransTimeMs = mMaxRetransTimeSupplier.getAsInt();
            // Every message exchange generates a new transaction id.
            mTransId = mRandom.nextInt() & 0xffffff;
            sendMessageDelayed(CMD_KICK, mInitialDelayMs);
        }

        private void handleKick() {
            // rfc8415#section-21.9: The elapsed time is measured from the time at which the
            // client sent the first message in the message exchange, and the elapsed-time field
            // is set to 0 in the first message in the message exchange.
            final long elapsedTimeMs;
            if (mRetransCount == 0) {
                elapsedTimeMs = 0;
                mTransStartMs = SystemClock.elapsedRealtime();
            } else {
                elapsedTimeMs = SystemClock.elapsedRealtime() - mTransStartMs;
            }

            sendPacket(mTransId, elapsedTimeMs);
            // Compares retransmission parameters and reschedules alarm accordingly.
            scheduleKick();
        }

        private void handleReceivedPacket(@NonNull final Dhcp6Packet packet) {
            // Technically it is valid for the server to not include a prefix in an IA in certain
            // scenarios (specifically in a reply to Renew / Rebind, which means: do not extend the
            // prefix, e.g. the list of prefix is empty). However, if prefix(es) do exist and all
            // prefixes are invalid, then we should just ignore this packet.
            if (!packet.isValid(mTransId, mClientDuid)) return;
            if (packet.getPrefixDelegation() != null && !packet.getPrefixDelegation().ipos.isEmpty()) {
                boolean allInvalidPrefixes = true;
                for (IaPrefixOption ipo : packet.getPrefixDelegation().ipos) {
                    if (ipo != null && ipo.isValid()) {
                        allInvalidPrefixes = false;
                        break;
                    }
                }
                if (allInvalidPrefixes) {
                    Log.w(TAG, "All IA_Prefix options included in the "
                            + packet.getClass().getSimpleName() + " are invalid, ignore it.");
                    return;
                }
            }
            if (packet.getAddressAssignment() != null && !packet.getAddressAssignment().iaAddrs.isEmpty()) {
                boolean allInvalidAddresses = true;
                for (IaAddressOption iao : packet.getAddressAssignment().iaAddrs) {
                    if (iao != null && iao.isValid()) {
                        allInvalidAddresses = false;
                        break;
                    }
                }
                if (allInvalidAddresses) {
                    Log.w(TAG, "All IA_Address options included in the "
                            + packet.getClass().getSimpleName() + " are invalid, ignore it.");
                    return;
                }
            }
            receivePacket(packet);
        }

        @Override
        public boolean processMessage(Message message) {
            if (super.processMessage(message) == HANDLED) {
                return HANDLED;
            }

            switch (message.what) {
                case CMD_KICK:
                    handleKick();
                    return HANDLED;
                case CMD_RECEIVED_PACKET:
                    handleReceivedPacket((Dhcp6Packet) message.obj);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        public void exit() {
            super.exit();
            mKickAlarm.cancel();
            mRetransTimeout = -1;
            mRetransCount = 0;
            mMaxRetransTimeMs = 0;
        }

        protected abstract boolean sendPacket(int transId, long elapsedTimeMs);
        protected abstract void receivePacket(Dhcp6Packet packet);
        // If the message exchange is considered to have failed according to the retransmission
        // mechanism(i.e. client has transmitted the message MRC times or MRD seconds has elapsed
        // since the first message transmission), this method will be called to roll back to Solicit
        // state and restart the configuration, and notify IpClient the DHCPv6 message exchange
        // failure if needed.
        protected void onMessageExchangeFailed() {}

        /**
         * Per RFC8415 section 15, each of the computations of a new RT includes a randomization
         * factor (RAND), which is a random number chosen with a uniform distribution between -0.1
         * and +0.1.
         */
        private double rand() {
            return mRandom.nextDouble() / 5 - 0.1;
        }

        protected void scheduleKick() {
            if (mRetransTimeout == -1) {
                // RT for the first message transmission is based on IRT.
                mRetransTimeout = mInitialRetransTimeMs + (long) (rand() * mInitialRetransTimeMs);
            } else {
                // RT for each subsequent message transmission is based on the previous value of RT.
                mRetransTimeout = 2 * mRetransTimeout + (long) (rand() * mRetransTimeout);
            }
            if (mMaxRetransTimeMs != 0 && mRetransTimeout > mMaxRetransTimeMs) {
                mRetransTimeout = mMaxRetransTimeMs + (long) (rand() * mMaxRetransTimeMs);
            }
            // Per RFC8415 section 18.2.4 and 18.2.5, MRD equals to the remaining time until
            // earliest T2(RenewState) or valid lifetimes of all leases in all IA have expired
            // (RebindState), and message exchange is terminated when the earliest time T2 is
            // reached, at which point client begins the Rebind message exchange, however, section
            // 15 says the message exchange fails(terminated) once MRD seconds have elapsed since
            // the client first transmitted the message. So far MRD is being used for Renew, Rebind
            // and Confirm message retransmission. Given we don't support Confirm message yet, we
            // can just use rebindTimeout and expirationTimeout on behalf of MRD which have been
            // scheduled in BoundState to simplify the implementation, therefore, we don't need to
            // explicitly assign the MRD in the subclasses.
            if (mMaxRetransCount != 0 && mRetransCount > mMaxRetransCount) {
                onMessageExchangeFailed();
                Log.i(TAG, "client has transmitted the message " + mMaxRetransCount
                        + " times, stopping retransmission");
                return;
            }
            mKickAlarm.schedule(SystemClock.elapsedRealtime() + mRetransTimeout);
            mRetransCount++;
        }
    }

    private void scheduleLeaseTimers() {
        int renewTimeout = 0;
        int rebindTimeout = 0;
        long deprecationTimeout = Long.MAX_VALUE;
        long expirationTimeout = Long.MAX_VALUE;

        if (mReplyPd != null) {
            renewTimeout = mReplyPd.t1;
            rebindTimeout = mReplyPd.t2;
            deprecationTimeout = Math.min(deprecationTimeout, mReplyPd.getMinimalPreferredLifetime());
            expirationTimeout = Math.min(expirationTimeout, mReplyPd.getMinimalValidLifetime());
        }

        if (mReplyAa != null) {
            final int naT1 = mReplyAa.t1;
            final int naT2 = mReplyAa.t2;
            if (renewTimeout == 0 || (naT1 > 0 && naT1 < renewTimeout)) {
                renewTimeout = naT1;
            }
            if (rebindTimeout == 0 || (naT2 > 0 && naT2 < rebindTimeout)) {
                rebindTimeout = naT2;
            }
            deprecationTimeout = Math.min(deprecationTimeout, mReplyAa.getMinimalPreferredLifetime());
            expirationTimeout = Math.min(expirationTimeout, mReplyAa.getMinimalValidLifetime());
        }

        if (expirationTimeout == Long.MAX_VALUE) {
            Log.w(TAG, "No valid lease found to schedule timers");
            return;
        }

        // rfc8415#section-14.2: if t1 and / or t2 are 0, the client chooses an appropriate value.
        // rfc8415#section-21.21: Recommended values for T1 and T2 are 0.5 and 0.8 times the
        // shortest preferred lifetime of the leases, respectively.
        if (renewTimeout == 0) {
            renewTimeout = (int) (deprecationTimeout * 0.5);
        }
        if (rebindTimeout == 0) {
            rebindTimeout = (int) (deprecationTimeout * 0.8);
        }

        if (renewTimeout >= rebindTimeout) {
            // skip RENEW
            renewTimeout = 0;
        }
        if (rebindTimeout >= expirationTimeout) {
            // skip REBIND
            rebindTimeout = 0;
        }

        final long now = SystemClock.elapsedRealtime();
        if (renewTimeout > 0) {
            mRenewAlarm.schedule(now + renewTimeout * (long) SECONDS);
            Log.d(TAG, "Scheduling DHCPv6 renewal in " + renewTimeout + "s");
        }
        if (rebindTimeout > 0) {
            mRebindAlarm.schedule(now + rebindTimeout * (long) SECONDS);
            Log.d(TAG, "Scheduling DHCPv6 rebind in " + rebindTimeout + "s");
        }
        mExpiryAlarm.schedule(now + expirationTimeout * (long) SECONDS);
        Log.d(TAG, "Scheduling DHCPv6 expiry in " + expirationTimeout + "s");
    }

    private void notifyPrefixDelegation(int result, @Nullable final List<IaPrefixOption> ipos) {
        mController.sendMessage(CMD_DHCP6_RESULT, result, 0, ipos);
    }

    private void notifyLease(int result, @NonNull final Dhcp6Lease lease) {
        mController.sendMessage(CMD_DHCP6_RESULT, result, 0, lease);
    }

    private void clearDhcp6State() {
        mAdvertisePd = null;
        mReplyPd = null;
        mAdvertiseAa = null;
        mReplyAa = null;
        mDnsServers.clear();
        mDomainList.clear();
        mServerDuid = null;
        mSolMaxRtMs = SOL_MAX_RT;
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendSolicitPacket(int transId, long elapsedTimeMs,
            @Nullable final ByteBuffer iapd, @Nullable final ByteBuffer iana) {
        final ByteBuffer packet = Dhcp6Packet.buildSolicitPacket(transId, elapsedTimeMs,
                mClientDuid,
                iapd != null ? iapd.array() : null,
                iana != null ? iana.array() : null,
                true /* rapidCommit */);
        return transmitPacket(packet, "solicit");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendRequestPacket(int transId, long elapsedTimeMs,
            @Nullable final ByteBuffer iapd, @Nullable final ByteBuffer iana) {
        final ByteBuffer packet = Dhcp6Packet.buildRequestPacket(transId, elapsedTimeMs,
                mClientDuid, mServerDuid,
                iapd != null ? iapd.array() : null,
                iana != null ? iana.array() : null);
        return transmitPacket(packet, "request");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendRenewPacket(int transId, long elapsedTimeMs,
            @Nullable final ByteBuffer iapd, @Nullable final ByteBuffer iana) {
        final ByteBuffer packet = Dhcp6Packet.buildRenewPacket(transId, elapsedTimeMs,
                mClientDuid, mServerDuid,
                iapd != null ? iapd.array() : null,
                iana != null ? iana.array() : null);
        return transmitPacket(packet, "renew");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendRebindPacket(int transId, long elapsedTimeMs,
            @Nullable final ByteBuffer iapd, @Nullable final ByteBuffer iana) {
        final ByteBuffer packet = Dhcp6Packet.buildRebindPacket(transId, elapsedTimeMs,
                mClientDuid,
                iapd != null ? iapd.array() : null,
                iana != null ? iana.array() : null);
        return transmitPacket(packet, "rebind");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendDeclinePacket(int transId, long elapsedTimeMs,
            @NonNull final Inet6Address addr) {
        final IaAddressOption declOption = new IaAddressOption(
                (short) IaAddressOption.LENGTH, addr, 0, 0);
        final AddressAssignment aa = new AddressAssignment(
                IAID, 0, 0, Collections.singletonList(declOption));
        final ByteBuffer packet = Dhcp6Packet.buildDeclinePacket(transId, elapsedTimeMs,
                mClientDuid, mServerDuid, aa.build().array());
        return transmitPacket(packet, "decline");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendConfirmPacket(int transId, long elapsedTimeMs,
            @NonNull final List<IaAddressOption> addrs) {
        final AddressAssignment aa = new AddressAssignment(IAID, 0, 0, addrs);
        final ByteBuffer packet = Dhcp6Packet.buildConfirmPacket(transId, elapsedTimeMs,
                mClientDuid, aa.build().array());
        return transmitPacket(packet, "confirm");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendReleasePacket(int transId, long elapsedTimeMs,
            @NonNull final List<IaAddressOption> addrs) {
        final AddressAssignment aa = new AddressAssignment(IAID, 0, 0, addrs);
        final ByteBuffer packet = Dhcp6Packet.buildReleasePacket(transId, elapsedTimeMs,
                mClientDuid, mServerDuid, aa.build().array());
        return transmitPacket(packet, "release");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendInfoRequestPacket(int transId, long elapsedTimeMs) {
        final ByteBuffer packet = Dhcp6Packet.buildInfoRequestPacket(transId, elapsedTimeMs,
                mClientDuid);
        return transmitPacket(packet, "information-request");
    }

    /**
     * Parent state at which client does initialization of interface and packet handler, also
     * processes the CMD_STOP_DHCP6 command in this state which child states don't handle.
     */
    class StartedState extends State {
        @Override
        public void enter() {
            clearDhcp6State();
            mDhcp6PacketDispatcher.registerHandler(
                    mDhcp6MessageHandler,
                    // register the expected DHCPv6 message types
                    Dhcp6Packet.DHCP6_MESSAGE_TYPE_ADVERTISE,
                    Dhcp6Packet.DHCP6_MESSAGE_TYPE_REPLY
            );
        }

        @Override
        public void exit() {
            mDhcp6PacketDispatcher.unregisterHandler(mDhcp6MessageHandler);
            clearDhcp6State();
        }

        @Override
        public boolean processMessage(Message message) {
            super.processMessage(message);
            switch (message.what) {
                case CMD_STOP_DHCP6:
                    transitionTo(mStoppedState);
                    return HANDLED;
                case CMD_START_DHCP6: {
                    final int newMode = (message.arg1 != 0) ? message.arg1 : MODE_IA_PD;
                    if (newMode == mMode) {
                        return HANDLED;
                    }
                    if (mMode == MODE_INFO_REQUEST && (newMode == MODE_IA_NA || newMode == MODE_DUAL)) {
                        mMode = newMode;
                        transitionTo(mSolicitState);
                    } else if ((mMode == MODE_IA_PD && newMode == MODE_IA_NA)
                            || (mMode == MODE_IA_NA && newMode == MODE_IA_PD)
                            || newMode == MODE_DUAL) {
                        mMode = MODE_DUAL;
                        transitionTo(mSolicitState);
                    }
                    return HANDLED;
                }
                default:
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * Initial state of DHCPv6 state machine.
     */
    class StoppedState extends State {
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_START_DHCP6:
                    mMode = (message.arg1 != 0) ? message.arg1 : MODE_IA_PD;
                    if (mMode == MODE_INFO_REQUEST) {
                        transitionTo(mInfoRequestState);
                    } else {
                        transitionTo(mSolicitState);
                    }
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * Client (re)transmits a Solicit message to locate DHCPv6 servers and processes the Advertise
     * message in this state.
     *
     * Note: Not implement DHCPv6 server selection, always request the first Advertise we receive.
     */
    class SolicitState extends MessageExchangeState {
        SolicitState() {
            // First Solicit message should be delayed by a random amount of time between 0
            // and SOL_MAX_DELAY(1s).
            super((int) (new Random().nextDouble() * SECONDS) /* delay */, SOL_TIMEOUT /* IRT */,
                    0 /* MRC */, () -> mSolMaxRtMs /* MRT */);
        }

        @Override
        public void enter() {
            super.enter();
        }

        @Override
        protected boolean sendPacket(int transId, long elapsedTimeMs) {
            final ByteBuffer pdBuf = (mMode & MODE_IA_PD) != 0
                    ? new PrefixDelegation(IAID, 0, 0,
                            Collections.singletonList(new IaPrefixOption((short) IaPrefixOption.LENGTH,
                                    0, 0, (byte) RFC7421_PREFIX_LENGTH, new byte[16]))).build()
                    : null;
            final ByteBuffer naBuf = (mMode & MODE_IA_NA) != 0
                    ? new AddressAssignment(IAID, 0, 0, Collections.emptyList()).build()
                    : null;
            return sendSolicitPacket(transId, elapsedTimeMs, pdBuf, naBuf);
        }

        @Override
        protected void receivePacket(Dhcp6Packet packet) {
            final PrefixDelegation pd = packet.getPrefixDelegation();
            final AddressAssignment aa = packet.getAddressAssignment();

            if (pd != null && pd.statusCode == Dhcp6Packet.STATUS_NO_PREFIX_AVAIL) {
                Log.w(TAG, "Server responded to Solicit without available prefix, ignoring");
                return;
            }
            if (aa != null && aa.statusCode == Dhcp6Packet.STATUS_NO_ADDRS_AVAIL) {
                Log.w(TAG, "Server responded to Solicit without available address, ignoring");
                return;
            }

            mDnsServers.clear();
            mDnsServers.addAll(packet.getDnsServers());
            mDomainList.clear();
            mDomainList.addAll(packet.getDomainList());

            if (packet instanceof Dhcp6AdvertisePacket) {
                Log.d(TAG, "Get lease options from Advertise: pd=" + pd + ", aa=" + aa);
                mAdvertisePd = pd;
                mAdvertiseAa = aa;
                mServerDuid = packet.getServerDuid();
                mSolMaxRtMs = packet.getSolMaxRtMs().orElse(mSolMaxRtMs);
                transitionTo(mRequestState);
            } else if (packet instanceof Dhcp6ReplyPacket) {
                if (!packet.mRapidCommit) {
                    Log.e(TAG, "Server responded to Solicit with Reply without rapid commit option"
                            + ", ignoring");
                    return;
                }
                Log.d(TAG, "Get lease options from RapidCommit Reply: pd=" + pd + ", aa=" + aa);
                mReplyPd = pd;
                mReplyAa = aa;
                mServerDuid = packet.getServerDuid();
                mSolMaxRtMs = packet.getSolMaxRtMs().orElse(mSolMaxRtMs);
                transitionTo(mBoundState);
            }
        }
    }

    /**
     * Client (re)transmits a Request message to request configuration from a specific server and
     * process the Reply message in this state.
     */
    class RequestState extends MessageExchangeState {
        RequestState() {
            super(0 /* delay */, REQ_TIMEOUT /* IRT */, REQ_MAX_RC /* MRC */,
                    () -> REQ_MAX_RT /* MRT */);
        }

        @Override
        protected boolean sendPacket(int transId, long elapsedTimeMs) {
            final ByteBuffer pdBuf = mAdvertisePd != null ? mAdvertisePd.build() : null;
            final ByteBuffer naBuf = mAdvertiseAa != null ? mAdvertiseAa.build() : null;
            return sendRequestPacket(transId, elapsedTimeMs, pdBuf, naBuf);
        }

        @Override
        protected void receivePacket(Dhcp6Packet packet) {
            if (!(packet instanceof Dhcp6ReplyPacket)) return;
            final PrefixDelegation pd = packet.getPrefixDelegation();
            final AddressAssignment aa = packet.getAddressAssignment();
            if (pd != null && pd.statusCode == Dhcp6Packet.STATUS_NO_PREFIX_AVAIL) {
                Log.w(TAG, "Server responded to Request without available prefix, restart Solicit");
                transitionTo(mSolicitState);
                return;
            }
            if (aa != null && aa.statusCode == Dhcp6Packet.STATUS_NO_ADDRS_AVAIL) {
                Log.w(TAG, "Server responded to Request without available address, restart Solicit");
                transitionTo(mSolicitState);
                return;
            }
            Log.d(TAG, "Get lease options from Reply: pd=" + pd + ", aa=" + aa);
            mReplyPd = pd;
            mReplyAa = aa;
            mDnsServers.clear();
            mDnsServers.addAll(packet.getDnsServers());
            mDomainList.clear();
            mDomainList.addAll(packet.getDomainList());
            mSolMaxRtMs = packet.getSolMaxRtMs().orElse(mSolMaxRtMs);
            transitionTo(mBoundState);
        }

        @Override
        protected void onMessageExchangeFailed() {
            transitionTo(mSolicitState);
        }
    }

    /**
     * Parent state of other states at which client has already obtained the lease from server.
     */
    class HaveLeaseState extends State {
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_DHCP6_PD_EXPIRE:
                    final Dhcp6Lease expiredLease = new Dhcp6Lease(
                            mReplyPd != null ? mReplyPd.getValidIaPrefixes() : null,
                            mReplyAa != null ? mReplyAa.getValidIaAddresses() : null,
                            Collections.emptyList(), Collections.emptyList());
                    if (mMode == MODE_IA_PD) {
                        notifyPrefixDelegation(DHCP6_PD_PREFIX_EXPIRED, expiredLease.ipos);
                    } else {
                        notifyLease(DHCP6_NA_ADDRESS_EXPIRED, expiredLease);
                    }
                    transitionTo(mSolicitState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        public void exit() {
            // Clear any extant alarms.
            mRenewAlarm.cancel();
            mRebindAlarm.cancel();
            mExpiryAlarm.cancel();
            clearDhcp6State();
        }
    }

    /**
     * Client has already obtained the lease from server and stays in Bound state until T1 expires.
     */
    class BoundState extends State {
        @Override
        public void enter() {
            super.enter();
            scheduleLeaseTimers();
            final Dhcp6Lease lease = new Dhcp6Lease(
                    mReplyPd != null ? mReplyPd.getValidIaPrefixes() : null,
                    mReplyAa != null ? mReplyAa.getValidIaAddresses() : null,
                    new ArrayList<>(mDnsServers),
                    new ArrayList<>(mDomainList));
            if (mMode == MODE_IA_PD) {
                notifyPrefixDelegation(DHCP6_PD_SUCCESS, lease.ipos);
            } else {
                notifyLease(DHCP6_NA_SUCCESS, lease);
            }
        }

        @Override
        public boolean processMessage(Message message) {
            super.processMessage(message);
            switch (message.what) {
                case CMD_DHCP6_PD_RENEW:
                    transitionTo(mRenewState);
                    return HANDLED;
                case CMD_REBIND_DHCP6:
                    transitionTo(mRebindState);
                    return HANDLED;
                case CMD_DECLINE_DHCP6:
                    final Inet6Address declinedAddr = (Inet6Address) message.obj;
                    sendDeclinePacket((mRandom.nextInt() & 0xffffff), 0, declinedAddr);
                    transitionTo(mSolicitState);
                    return HANDLED;
                case CMD_CONFIRM_DHCP6:
                    if (mReplyAa != null && !mReplyAa.getValidIaAddresses().isEmpty()) {
                        sendConfirmPacket((mRandom.nextInt() & 0xffffff), 0, mReplyAa.getValidIaAddresses());
                    }
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * Per RFC8415 section 18.2.10.1: Reply for Renew or Rebind.
     */
    abstract class ReacquireState extends MessageExchangeState {
        ReacquireState(final int irt, final int mrt) {
            super(0 /* delay */, irt, 0 /* MRC */, () -> mrt /* MRT */);
        }

        @Override
        public void enter() {
            super.enter();
        }

        @Override
        protected void receivePacket(Dhcp6Packet packet) {
            if (!(packet instanceof Dhcp6ReplyPacket)) return;
            final PrefixDelegation pd = packet.getPrefixDelegation();
            final AddressAssignment aa = packet.getAddressAssignment();

            if (pd != null && pd.statusCode == Dhcp6Packet.STATUS_NO_PREFIX_AVAIL) {
                Log.w(TAG, "Server responded to Renew/Rebind without available prefix, ignoring");
                return;
            }
            if (aa != null && aa.statusCode == Dhcp6Packet.STATUS_NO_ADDRS_AVAIL) {
                Log.w(TAG, "Server responded to Renew/Rebind without available address, ignoring");
                return;
            }

            Log.d(TAG, "Get lease options from Reply as response to Renew/Rebind pd=" + pd + ", aa=" + aa);
            if ((pd == null || pd.ipos.isEmpty()) && (aa == null || aa.iaAddrs.isEmpty())) {
                return;
            }
            if (pd != null) mReplyPd = pd;
            if (aa != null) mReplyAa = aa;
            mDnsServers.clear();
            mDnsServers.addAll(packet.getDnsServers());
            mDomainList.clear();
            mDomainList.addAll(packet.getDomainList());
            mServerDuid = packet.getServerDuid();
            transitionTo(mBoundState);
        }
    }

    /**
     * Client enters Renew state when T1 expires.
     */
    class RenewState extends ReacquireState {
        RenewState() {
            super(REN_TIMEOUT, REN_MAX_RT);
        }

        @Override
        public boolean processMessage(Message message) {
            if (super.processMessage(message) == HANDLED) {
                return HANDLED;
            }
            switch (message.what) {
                case CMD_DHCP6_PD_REBIND:
                    transitionTo(mRebindState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        protected boolean sendPacket(int transId, long elapsedTimeMs) {
            final List<IaPrefixOption> toBeRenewedPd = mReplyPd != null
                    ? mReplyPd.getRenewableIaPrefixes() : Collections.emptyList();
            final List<IaAddressOption> toBeRenewedAa = mReplyAa != null
                    ? mReplyAa.getRenewableIaAddresses() : Collections.emptyList();
            if (toBeRenewedPd.isEmpty() && toBeRenewedAa.isEmpty()) {
                if (DBG) Log.d(TAG, "Do not send Renew message due to no renewable prefix or address.");
                return false;
            }
            final ByteBuffer pdBuf = !toBeRenewedPd.isEmpty() ? mReplyPd.build(toBeRenewedPd) : null;
            final ByteBuffer naBuf = !toBeRenewedAa.isEmpty() ? mReplyAa.build(toBeRenewedAa) : null;
            return sendRenewPacket(transId, elapsedTimeMs, pdBuf, naBuf);
        }
    }

    /**
     * Client enters Rebind state when T2 expires.
     */
    class RebindState extends ReacquireState {
        RebindState() {
            super(REB_TIMEOUT, REB_MAX_RT);
        }

        @Override
        public void enter() {
            super.enter();
            mRenewAlarm.cancel();
            mRebindAlarm.cancel();
        }

        @Override
        protected boolean sendPacket(int transId, long elapsedTimeMs) {
            final List<IaPrefixOption> toBeReboundPd = mReplyPd != null
                    ? mReplyPd.getRenewableIaPrefixes() : Collections.emptyList();
            final List<IaAddressOption> toBeReboundAa = mReplyAa != null
                    ? mReplyAa.getRenewableIaAddresses() : Collections.emptyList();
            if (toBeReboundPd.isEmpty() && toBeReboundAa.isEmpty()) {
                if (DBG) Log.d(TAG, "Do not send Rebind message due to no renewable prefix or address.");
                return false;
            }
            final ByteBuffer pdBuf = !toBeReboundPd.isEmpty() ? mReplyPd.build(toBeReboundPd) : null;
            final ByteBuffer naBuf = !toBeReboundAa.isEmpty() ? mReplyAa.build(toBeReboundAa) : null;
            return sendRebindPacket(transId, elapsedTimeMs, pdBuf, naBuf);
        }
    }

    /**
     * Stateless DHCPv6: client transmits Information-Request and receives configuration parameters.
     */
    class InfoRequestState extends MessageExchangeState {
        InfoRequestState() {
            super(0 /* delay */, SOL_TIMEOUT /* IRT */, 5 /* MRC */, () -> mSolMaxRtMs /* MRT */);
        }

        @Override
        protected boolean sendPacket(int transId, long elapsedTimeMs) {
            return sendInfoRequestPacket(transId, elapsedTimeMs);
        }

        @Override
        protected void receivePacket(Dhcp6Packet packet) {
            if (!(packet instanceof Dhcp6ReplyPacket)) return;
            Log.d(TAG, "Get DNS/Domain options from Info-Request Reply: " + packet.getDnsServers());
            mDnsServers.clear();
            mDnsServers.addAll(packet.getDnsServers());
            mDomainList.clear();
            mDomainList.addAll(packet.getDomainList());
            final Dhcp6Lease lease = new Dhcp6Lease(null, null,
                    new ArrayList<>(mDnsServers), new ArrayList<>(mDomainList));
            notifyLease(DHCP6_INFO_SUCCESS, lease);
            transitionTo(mStoppedState);
        }

        @Override
        protected void onMessageExchangeFailed() {
            Log.w(TAG, "Information-Request failed");
            transitionTo(mStoppedState);
        }
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean transmitPacket(@NonNull final ByteBuffer buf,
            @NonNull final String description) {
        if (DBG) {
            Log.d(TAG, "Multicasting " + description + " to ff02::1:2" + " packet raw data: "
                    + HexDump.toHexString(buf.array(), 0, buf.limit()));
        }
        return mDhcp6PacketDispatcher.transmitPacket(buf) > 0;
    }
}
