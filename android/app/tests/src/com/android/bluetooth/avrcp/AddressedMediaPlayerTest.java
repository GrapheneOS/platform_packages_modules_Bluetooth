package com.android.bluetooth.avrcp;

import android.bluetooth.BluetoothAvrcp;
import android.media.session.MediaSession;
import android.media.session.MediaSession.QueueItem;
import android.media.MediaDescription;
import android.media.MediaMetadata;
import android.os.Bundle;
import android.test.AndroidTestCase;
import android.util.Log;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;

import static org.mockito.Mockito.*;

public class AddressedMediaPlayerTest extends AndroidTestCase {

    public void testHandlePassthroughCmd() {
        MediaController mockController = mock(com.android.bluetooth.avrcp.MediaController.class);
        MediaController.TransportControls mockTransport = mock(MediaController.TransportControls.class);
        AvrcpMediaRspInterface mockRspInterface = mock(AvrcpMediaRspInterface.class);

        when(mockController.getTransportControls()).thenReturn(mockTransport);
        AddressedMediaPlayer myMediaPlayer = new AddressedMediaPlayer(mockRspInterface);


        // Test rewind
        myMediaPlayer.handlePassthroughCmd(BluetoothAvrcp.PASSTHROUGH_ID_REWIND,
                                           AvrcpConstants.KEY_STATE_PRESS,
                                           null,
                                           mockController);
        verify(mockTransport).rewind();

        // Test fast forward
        myMediaPlayer.handlePassthroughCmd(BluetoothAvrcp.PASSTHROUGH_ID_FAST_FOR,
                                           AvrcpConstants.KEY_STATE_PRESS,
                                           null,
                                           mockController);
        verify(mockTransport).fastForward();

        // Test play
        myMediaPlayer.handlePassthroughCmd(BluetoothAvrcp.PASSTHROUGH_ID_PLAY,
                                           AvrcpConstants.KEY_STATE_PRESS,
                                           null,
                                           mockController);
        verify(mockTransport).play();

        // Test pause
        myMediaPlayer.handlePassthroughCmd(BluetoothAvrcp.PASSTHROUGH_ID_PAUSE,
                                           AvrcpConstants.KEY_STATE_PRESS,
                                           null,
                                           mockController);
        verify(mockTransport).pause();

        // Test stop
        myMediaPlayer.handlePassthroughCmd(BluetoothAvrcp.PASSTHROUGH_ID_STOP,
                                           AvrcpConstants.KEY_STATE_PRESS,
                                           null,
                                           mockController);
        verify(mockTransport).stop();

        // Test skip to next
        myMediaPlayer.handlePassthroughCmd(BluetoothAvrcp.PASSTHROUGH_ID_FORWARD,
                                           AvrcpConstants.KEY_STATE_PRESS,
                                           null,
                                           mockController);
        verify(mockTransport).skipToNext();

        // Test skip backwards
        myMediaPlayer.handlePassthroughCmd(BluetoothAvrcp.PASSTHROUGH_ID_BACKWARD,
                                           AvrcpConstants.KEY_STATE_PRESS,
                                           null,
                                           mockController);
        verify(mockTransport).skipToPrevious();

        // Test invalid key
        myMediaPlayer.handlePassthroughCmd(0xFF,
                                           AvrcpConstants.KEY_STATE_PRESS,
                                           null,
                                           mockController);
        verifyNoMoreInteractions(mockTransport);

        // Test key release
        myMediaPlayer.handlePassthroughCmd(BluetoothAvrcp.PASSTHROUGH_ID_PLAY,
                                           AvrcpConstants.KEY_STATE_RELEASE,
                                           null,
                                           mockController);
        verifyNoMoreInteractions(mockTransport);
    }
}
