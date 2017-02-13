package com.android.bluetooth.sap;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.android.btsap.SapApi.MsgHeader;

import com.google.protobuf.micro.CodedInputStreamMicro;
import com.google.protobuf.micro.CodedOutputStreamMicro;

import android.hardware.radio.V1_0.ISap;
import android.hardware.radio.V1_0.ISapCallback;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Handler;
import android.os.HwBinder;
import android.os.Message;
import android.os.RemoteException;
import android.util.Log;

public class SapRilReceiver implements Runnable {

    private static final String TAG = "SapRilReceiver";
    public static final boolean DEBUG = true;
    public static final boolean VERBOSE = true;

    private static final String SOCKET_NAME_RIL_BT = "sap_uim_socket1";
    // match with constant in ril.cpp - as in RIL.java
    private static final int SOCKET_OPEN_RETRY_MILLIS = 4 * 1000;

    LocalSocket mSocket = null;
    CodedOutputStreamMicro mRilBtOutStream = null;
    InputStream mRilBtInStream = null;

    SapCallback mSapCallback;
    volatile ISap mSapProxy = null;
    final AtomicLong mSapProxyCookie = new AtomicLong(0);
    final SapProxyDeathRecipient mSapProxyDeathRecipient;

    private Handler mSapServerMsgHandler = null;
    private Handler mSapServiceHandler = null;

    public static final int RIL_MAX_COMMAND_BYTES = (8 * 1024);
    byte[] buffer = new byte[RIL_MAX_COMMAND_BYTES];

    final class SapProxyDeathRecipient implements HwBinder.DeathRecipient {
        @Override
        public void serviceDied(long cookie) {
            // Deal with service going away
            Log.d(TAG, "serviceDied");
            // todo: temp hack to send delayed message so that rild is back up by then
            // mSapHandler.sendMessage(mSapHandler.obtainMessage(EVENT_SAP_PROXY_DEAD, cookie));
            mSapServerMsgHandler.sendMessageDelayed(
                    mSapServerMsgHandler.obtainMessage(SapServer.SAP_PROXY_DEAD, cookie),
                    SapServer.ISAP_GET_SERVICE_DELAY_MILLIS);
        }
    }

    private void sendSapMessage(SapMessage sapMessage) {
        if (sapMessage.getMsgType() < SapMessage.ID_RIL_BASE) {
            sendClientMessage(sapMessage);
        } else {
            sendRilIndMessage(sapMessage);
        }
    }

    private void removeOngoingReqAndSendMessage(int token, SapMessage sapMessage) {
        Integer reqType = SapMessage.sOngoingRequests.remove(token);
        if (VERBOSE) {
            Log.d(TAG, "removeOngoingReqAndSendMessage: token " + token + " reqType "
                            + (reqType == null ? "null" : SapMessage.getMsgTypeName(reqType)));
        }
        sendSapMessage(sapMessage);
    }

    class SapCallback extends ISapCallback.Stub {
        public void connectResponse(int token, int sapConnectRsp, int maxMsgSize) {
            Log.d(TAG, "connectResponse: token " + token + " sapConnectRsp " + sapConnectRsp
                            + " maxMsgSize " + maxMsgSize);
            SapMessage sapMessage = new SapMessage(SapMessage.ID_CONNECT_RESP);
            sapMessage.setConnectionStatus(sapConnectRsp);
            if (sapConnectRsp == SapMessage.CON_STATUS_ERROR_MAX_MSG_SIZE_UNSUPPORTED) {
                sapMessage.setMaxMsgSize(maxMsgSize);
            }
            sapMessage.setResultCode(SapMessage.INVALID_VALUE);
            removeOngoingReqAndSendMessage(token, sapMessage);
        }

        public void disconnectResponse(int token) {
            Log.d(TAG, "disconnectResponse: token " + token);
            SapMessage sapMessage = new SapMessage(SapMessage.ID_DISCONNECT_RESP);
            sapMessage.setResultCode(SapMessage.INVALID_VALUE);
            removeOngoingReqAndSendMessage(token, sapMessage);
        }

        public void disconnectIndication(int token, int disconnectType) {
            Log.d(TAG,
                    "disconnectIndication: token " + token + " disconnectType " + disconnectType);
            SapMessage sapMessage = new SapMessage(SapMessage.ID_RIL_UNSOL_DISCONNECT_IND);
            sapMessage.setDisconnectionType(disconnectType);
            sendSapMessage(sapMessage);
        }

        public void apduResponse(int token, int resultCode, ArrayList<Byte> apduRsp) {
            Log.d(TAG, "apduResponse: token " + token);
            SapMessage sapMessage = new SapMessage(SapMessage.ID_TRANSFER_APDU_RESP);
            sapMessage.setResultCode(resultCode);
            if (resultCode == SapMessage.RESULT_OK) {
                sapMessage.setApduResp(arrayListToPrimitiveArray(apduRsp));
            }
            removeOngoingReqAndSendMessage(token, sapMessage);
        }

        public void transferAtrResponse(int token, int resultCode, ArrayList<Byte> atr) {
            Log.d(TAG, "transferAtrResponse: token " + token + " resultCode " + resultCode);
            SapMessage sapMessage = new SapMessage(SapMessage.ID_TRANSFER_ATR_RESP);
            sapMessage.setResultCode(resultCode);
            if (resultCode == SapMessage.RESULT_OK) {
                sapMessage.setAtr(arrayListToPrimitiveArray(atr));
            }
            removeOngoingReqAndSendMessage(token, sapMessage);
        }

        public void powerResponse(int token, int resultCode) {
            Log.d(TAG, "powerResponse: token " + token + " resultCode " + resultCode);
            Integer reqType = SapMessage.sOngoingRequests.remove(token);
            if (VERBOSE) {
                Log.d(TAG, "powerResponse: reqType "
                                + (reqType == null ? "null" : SapMessage.getMsgTypeName(reqType)));
            }
            SapMessage sapMessage;
            if (reqType == SapMessage.ID_POWER_SIM_OFF_REQ) {
                sapMessage = new SapMessage(SapMessage.ID_POWER_SIM_OFF_RESP);
            } else if (reqType == SapMessage.ID_POWER_SIM_ON_REQ) {
                sapMessage = new SapMessage(SapMessage.ID_POWER_SIM_ON_RESP);
            } else {
                return;
            }
            sapMessage.setResultCode(resultCode);
            sendSapMessage(sapMessage);
        }

        public void resetSimResponse(int token, int resultCode) {
            Log.d(TAG, "resetSimResponse: token " + token + " resultCode " + resultCode);
            SapMessage sapMessage = new SapMessage(SapMessage.ID_RESET_SIM_RESP);
            sapMessage.setResultCode(resultCode);
            removeOngoingReqAndSendMessage(token, sapMessage);
        }

        public void statusIndication(int token, int status) {
            Log.d(TAG, "statusIndication: token " + token + " status " + status);
            SapMessage sapMessage = new SapMessage(SapMessage.ID_STATUS_IND);
            sapMessage.setStatusChange(status);
            sendSapMessage(sapMessage);
        }

        public void transferCardReaderStatusResponse(
                int token, int resultCode, int cardReaderStatus) {
            Log.d(TAG, "transferCardReaderStatusResponse: token " + token + " resultCode "
                            + resultCode + " cardReaderStatus " + cardReaderStatus);
            SapMessage sapMessage = new SapMessage(SapMessage.ID_TRANSFER_CARD_READER_STATUS_RESP);
            sapMessage.setResultCode(resultCode);
            if (resultCode == SapMessage.RESULT_OK) {
                sapMessage.setCardReaderStatus(cardReaderStatus);
            }
            removeOngoingReqAndSendMessage(token, sapMessage);
        }

        public void errorResponse(int token) {
            Log.d(TAG, "errorResponse: token " + token);
            // Since ERROR_RESP isn't supported by createUnsolicited(), keeping behavior same here
            // SapMessage sapMessage = new SapMessage(SapMessage.ID_ERROR_RESP);
            SapMessage sapMessage = new SapMessage(SapMessage.ID_RIL_UNKNOWN);
            sendSapMessage(sapMessage);
        }

        public void transferProtocolResponse(int token, int resultCode) {
            Log.d(TAG, "transferProtocolResponse: token " + token + " resultCode " + resultCode);
            SapMessage sapMessage = new SapMessage(SapMessage.ID_SET_TRANSPORT_PROTOCOL_RESP);
            sapMessage.setResultCode(resultCode);
            removeOngoingReqAndSendMessage(token, sapMessage);
        }
    }

    public static byte[] arrayListToPrimitiveArray(List<Byte> bytes) {
        byte[] ret = new byte[bytes.size()];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = bytes.get(i);
        }
        return ret;
    }

    public ISap getSapProxy() {
        if (mSapProxy != null) {
            return mSapProxy;
        }

        try {
            mSapProxy = ISap.getService(SOCKET_NAME_RIL_BT);
            if (mSapProxy != null) {
                Log.d(TAG, "getSapProxy: mSapProxy != null; calling setCallback()");
                mSapProxy.linkToDeath(mSapProxyDeathRecipient, mSapProxyCookie.incrementAndGet());
                mSapProxy.setCallback(mSapCallback);
            } else {
                Log.e(TAG, "getSapProxy: mSapProxy == null");
            }
        } catch (RemoteException | RuntimeException e) {
            mSapProxy = null;

            // if service is not up, treat it like death notification to try to get service again
            mSapServerMsgHandler.sendMessageDelayed(
                    mSapServerMsgHandler.obtainMessage(
                            SapServer.SAP_PROXY_DEAD, mSapProxyCookie.get()),
                    SapServer.ISAP_GET_SERVICE_DELAY_MILLIS);

            Log.e(TAG, "getSapProxy: exception", e);
        }
        return mSapProxy;
    }

    public void resetSapProxy() {
        mSapProxy = null;
    }

    public SapRilReceiver(Handler SapServerMsgHandler, Handler sapServiceHandler) {
        mSapServerMsgHandler = SapServerMsgHandler;
        mSapServiceHandler = sapServiceHandler;
        mSapCallback = new SapCallback();
        mSapProxyDeathRecipient = new SapProxyDeathRecipient();
        mSapProxy = getSapProxy();
    }

    /**
     * Open the RIL-BT socket in rild. Will continuously try to open the BT socket until
     * success. (Based on the approach used to open the rild socket in telephony)
     * @return The socket handle
     */
    public static LocalSocket openRilBtSocket() {
        int retryCount = 0;
        LocalSocket rilSocket = null;

        for (;;) {
            LocalSocketAddress address;

            try {
                rilSocket = new LocalSocket();
                address = new LocalSocketAddress(SOCKET_NAME_RIL_BT,
                        LocalSocketAddress.Namespace.RESERVED);
                rilSocket.connect(address);
                break; // Socket opened
            } catch (IOException ex){
                try {
                    if (rilSocket != null) {
                        rilSocket.close();
                    }
                } catch (IOException ex2) {
                    //ignore failure to close after failure to connect
                }

                // don't print an error message after the the first time
                // or after the 8th time
                if (retryCount == 8) {
                    Log.e (TAG,
                        "Couldn't find '" + SOCKET_NAME_RIL_BT
                        + "' socket after " + retryCount
                        + " times, continuing to retry silently");
                } else if (retryCount > 0 && retryCount < 8) {
                    Log.i (TAG,
                        "Couldn't find '" + SOCKET_NAME_RIL_BT
                        + "' socket; retrying after timeout");
                    if (VERBOSE) Log.w(TAG, ex);
                }

                try {
                    Thread.sleep(SOCKET_OPEN_RETRY_MILLIS);
                } catch (InterruptedException er) {
                }

                retryCount++;
                continue;
            }
        }
        return rilSocket;
    }


    public CodedOutputStreamMicro getRilBtOutStream() {
        return mRilBtOutStream;
    }

    /**
     * Notify SapServer that this class is ready for shutdown.
     */
    private void notifyShutdown() {
        if (DEBUG) Log.i(TAG, "notifyShutdown()");
        // If we are already shutdown, don't bother sending a notification.
        synchronized (this) {
            if (mSocket != null) sendShutdownMessage();
        }
    }

    /**
     * This will terminate the SapRilReceiver thread, by closing the RIL-BT in-/output
     * streams.
     */
    public void shutdown() {
        if (DEBUG) Log.i(TAG, "shutdown()");

        /* On Android you need to close the IOstreams using Socket.shutdown*
         * The IOstream close must not be used, as it some how decouples the
         * stream from the socket, and when the socket is closed, the pending
         * reads never return nor throw and exception.
         * Hence here we use the shutdown method: */
        synchronized (this) {
            if (mSocket != null) {
                try {
                    mSocket.shutdownOutput();
                } catch (IOException e) {}
                try {
                    mSocket.shutdownInput();
                } catch (IOException e) {}
                try {
                    mSocket.close();
                } catch (IOException ex) {
                    if (VERBOSE) Log.e(TAG,"Uncaught exception", ex);
                } finally {
                    mSocket = null;
                }
            }
        }
    }

    /**
     * Read the message into buffer
     * @param is
     * @param buffer
     * @return the length of the message
     * @throws IOException
     */
    private static int readMessage(InputStream is, byte[] buffer) throws IOException {
        int countRead;
        int offset;
        int remaining;
        int messageLength;

        // Read in the length of the message
        offset = 0;
        remaining = 4;
        do {
            countRead = is.read(buffer, offset, remaining);

            if (countRead < 0 ) {
                Log.e(TAG, "Hit EOS reading message length");
                return -1;
            }

            offset += countRead;
            remaining -= countRead;
        } while (remaining > 0);

        messageLength = ((buffer[0] & 0xff) << 24)
                | ((buffer[1] & 0xff) << 16)
                | ((buffer[2] & 0xff) << 8)
                | (buffer[3] & 0xff);
        if (VERBOSE) Log.e(TAG,"Message length found to be: "+messageLength);
        // Read the message
        offset = 0;
        remaining = messageLength;
        do {
            countRead = is.read(buffer, offset, remaining);

            if (countRead < 0 ) {
                Log.e(TAG, "Hit EOS reading message.  messageLength=" + messageLength
                        + " remaining=" + remaining);
                return -1;
            }

            offset += countRead;
            remaining -= countRead;
        } while (remaining > 0);

        return messageLength;
    }

    /**
     * The RIL reader thread. Will handle open of the RIL-BT socket, and notify
     * SapServer when done.
     */
    @Override
    public void run() {

        try {
            if (VERBOSE) Log.i(TAG, "Starting RilBtReceiverThread...");

            mSocket = openRilBtSocket();
            mRilBtInStream = mSocket.getInputStream();
            mRilBtOutStream = CodedOutputStreamMicro.newInstance(mSocket.getOutputStream());

            // Notify the SapServer that we have connected to the RilBtSocket
            sendRilConnectMessage();

            // The main loop - read messages and forward to SAP server
            for (;;) {
                SapMessage sapMsg = null;
                MsgHeader rilMsg;

                if (VERBOSE) Log.i(TAG, "Waiting for incoming message...");
                int length = readMessage(mRilBtInStream, buffer);

                SapService.notifyUpdateWakeLock(mSapServiceHandler);

                if (length == -1) {
                    if (DEBUG) Log.i(TAG, "EOF reached - closing down.");
                    break;
                }

                CodedInputStreamMicro msgStream =
                        CodedInputStreamMicro.newInstance(buffer, 0, length);

                rilMsg = MsgHeader.parseFrom(msgStream);

                if (VERBOSE) Log.i(TAG, "Message received.");

                sapMsg = SapMessage.newInstance(rilMsg);

                if (sapMsg != null && sapMsg.getMsgType() != SapMessage.INVALID_VALUE)
                {
                    if (sapMsg.getMsgType() < SapMessage.ID_RIL_BASE) {
                        sendClientMessage(sapMsg);
                    } else {
                        sendRilIndMessage(sapMsg);
                    }
                } // else simply ignore it
            }

        } catch (IOException e) {
            notifyShutdown(); /* Only needed in case of a connection error */
            Log.i(TAG, "'" + SOCKET_NAME_RIL_BT + "' socket inputStream closed", e);

        } finally {
            Log.i(TAG, "Disconnected from '" + SOCKET_NAME_RIL_BT + "' socket");
        }
    }

    /**
     * Notify SapServer that the RIL socket is connected
     */
    private void sendRilConnectMessage() {
        if (mSapServerMsgHandler != null) {
            mSapServerMsgHandler.sendEmptyMessage(SapServer.SAP_MSG_RIL_CONNECT);
        }
    }

    /**
     * Send reply (solicited) message from the RIL to the Sap Server Handler Thread
     * @param sapMsg The message to send
     */
    private void sendClientMessage(SapMessage sapMsg) {
        Message newMsg = mSapServerMsgHandler.obtainMessage(SapServer.SAP_MSG_RFC_REPLY, sapMsg);
        mSapServerMsgHandler.sendMessage(newMsg);
    }

    /**
     * Send a shutdown signal to SapServer to indicate the
     */
    private void sendShutdownMessage() {
        if (mSapServerMsgHandler != null) {
            mSapServerMsgHandler.sendEmptyMessage(SapServer.SAP_RIL_SOCK_CLOSED);
        }
    }

    /**
     * Send indication (unsolicited) message from RIL to the Sap Server Handler Thread
     * @param sapMsg The message to send
     */
    private void sendRilIndMessage(SapMessage sapMsg) {
        Message newMsg = mSapServerMsgHandler.obtainMessage(SapServer.SAP_MSG_RIL_IND, sapMsg);
        mSapServerMsgHandler.sendMessage(newMsg);
    }

}
