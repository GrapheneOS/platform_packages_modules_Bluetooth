# Lint as: python3
"""Tests for Bluetooth A2DP audio streamming."""

import time

from mobly import asserts
from mobly import test_runner
from mobly import signals

from blueberry.controllers import android_bt_target_device
from blueberry.utils import blueberry_base_test
from blueberry.utils import bt_audio_utils
from blueberry.utils import bt_constants
from blueberry.utils import bt_test_utils

# Number of seconds for A2DP audio check.
A2DP_AUDIO_CHECK_TIMEOUT_SEC = 3

# Number of seconds for duration of reference audio.
REFERENCE_AUDIO_DURATION_SEC = 1.0

# Default threshold of the mean opinion score (MOS).
MOS_THRESHOLD = 4.5

# The audio parameters for creating a sine wave.
AUDIO_PARAMS = {
    'file_path': '/sdcard/Music',
    'frequency': 480,
    'channel': 2,
    'sample_rate': 48000,
    'sample_format': 16,
    'duration_sec': 60
}


class BluetoothA2dpTest(blueberry_base_test.BlueberryBaseTest):
  """Test class for Bluetooth A2DP test.

  This test uses a fixed frequency sine wave to be the reference audio, makes a
  DUT play this audio and then starts audio capture from a connected Bluetooth
  sink device, measures mean opinion score (MOS) of the recorded audio and
  compares the MOS with a threshold to detemine the test result.
  """

  def setup_class(self):
    """Standard Mobly setup class."""
    super(BluetoothA2dpTest, self).setup_class()

    # Threshold of the MOS to determine a test result. Default value is 4.5.
    self.threshold = float(self.user_params.get('mos_threshold', MOS_THRESHOLD))

    self.phone = self.android_devices[0]
    self.phone.init_setup()
    self.phone.sl4a_setup()

    # Generates a sine wave to be reference audio in comparison, and push it to
    # the phone storage.
    self.audio_file_on_device, self.audio_file_on_host = (
        bt_audio_utils.generate_sine_wave_to_device(
            self.phone,
            AUDIO_PARAMS['file_path'],
            AUDIO_PARAMS['frequency'],
            AUDIO_PARAMS['channel'],
            AUDIO_PARAMS['sample_rate'],
            AUDIO_PARAMS['sample_format'],
            AUDIO_PARAMS['duration_sec'])
        )

    # Trims the audio to 1 second duration for reference.
    self.reference_audio_file = bt_audio_utils.trim_audio(
        audio_file=self.audio_file_on_host,
        duration_sec=REFERENCE_AUDIO_DURATION_SEC)

    self.derived_bt_device = self.derived_bt_devices[0]
    self.derived_bt_device.factory_reset_bluetooth()
    self.derived_bt_device.activate_pairing_mode()
    self.mac_address = self.derived_bt_device.get_bluetooth_mac_address()
    self.phone.pair_and_connect_bluetooth(self.mac_address)

    # Sleep until the connection stabilizes.
    time.sleep(3)

    # Adds the phone to be the secondary device in the android-to-android case.
    if isinstance(self.derived_bt_device,
                  android_bt_target_device.AndroidBtTargetDevice):
      self.derived_bt_device.add_sec_ad_device(self.phone)

  def assert_a2dp_expected_status(self, is_playing, fail_msg):
    """Asserts that A2DP audio is in the expected status.

    Args:
      is_playing: bool, True if A2DP audio is playing as expected.
      fail_msg: string, a message explaining the details of test failure.
    """
    bt_test_utils.wait_until(
        timeout_sec=A2DP_AUDIO_CHECK_TIMEOUT_SEC,
        condition_func=self.phone.mbs.btIsA2dpPlaying,
        func_args=[self.mac_address],
        expected_value=is_playing,
        exception=signals.TestFailure(fail_msg))

  def test_play_a2dp_audio(self):
    """Test for playing A2DP audio through Bluetooth."""

    # Plays media audio from the phone.
    audio_file_url = 'file://' + self.audio_file_on_device
    if not self.phone.sl4a.mediaPlayOpen(audio_file_url):
      raise signals.TestError(
          'Failed to open and play "%s" on the phone "%s".' %
          (self.audio_file_on_device, self.phone.serial))
    self.phone.sl4a.mediaPlayStart()

    # Starts audio capture for Bluetooth audio stream.
    self.derived_bt_device.start_audio_capture()

    # Stops audio capture and generates an recorded audio file.
    recorded_audio_file = self.derived_bt_device.stop_audio_capture()
    self.phone.sl4a.mediaPlayStop()
    self.phone.sl4a.mediaPlayClose()

    # Measures MOS for the recorded audio.
    mos = bt_audio_utils.measure_audio_mos(recorded_audio_file,
                                           self.reference_audio_file)

    # Asserts that the measured MOS should be more than the threshold.
    asserts.assert_true(
        mos >= self.threshold,
        'MOS of the recorded audio "%.3f" is lower than the threshold "%.3f".' %
        (mos, self.threshold))

  def test_resume_a2dp_audio_after_phone_call_ended(self):
    """Test for resuming A2DP audio after a phone call ended.

    Tests that A2DP audio can be paused when receiving a incoming phone call,
    and resumed after this phone call ended.
    """
    # Checks if two android device exist.
    if len(self.android_devices) < 2:
      raise signals.TestError('This test requires two android devices.')
    pri_phone = self.phone
    sec_phone = self.android_devices[1]
    sec_phone.init_setup()
    pri_number = pri_phone.dimensions.get('phone_number')
    if not pri_number:
      raise signals.TestError('Please set the dimension "phone_number" to the '
                              'primary phone.')
    sec_number = sec_phone.dimensions.get('phone_number')
    if not sec_number:
      raise signals.TestError('Please set the dimension "phone_number" to the '
                              'secondary phone.')

    # Plays media audio from the phone.
    audio_file_url = 'file://' + self.audio_file_on_device
    if not self.phone.sl4a.mediaPlayOpen(audio_file_url):
      raise signals.TestError(
          'Failed to open and play "%s" on the phone "%s".' %
          (self.audio_file_on_device, self.phone.serial))
    self.phone.sl4a.mediaPlayStart()

    # Checks if A2DP audio is playing.
    self.assert_a2dp_expected_status(
        is_playing=True,
        fail_msg='A2DP audio is not playing.')

    try:
      # Makes a incoming phone call.
      sec_phone.sl4a.telecomCallNumber(pri_number)
      sec_phone.log.info('Made a phone call to device "%s".' % pri_phone.serial)
      pri_phone.log.info('Waiting for the incoming call from device "%s"...'
                         % sec_phone.serial)

      is_ringing = pri_phone.wait_for_call_state(
          bt_constants.CALL_STATE_RINGING,
          bt_constants.CALL_STATE_TIMEOUT_SEC)
      if not is_ringing:
        raise signals.TestError(
            'Timed out after %ds waiting for the incoming call from device '
            '"%s".' % (bt_constants.CALL_STATE_TIMEOUT_SEC, sec_phone.serial))

      # Checks if A2DP audio is paused.
      self.assert_a2dp_expected_status(
          is_playing=False,
          fail_msg='A2DP audio is not paused when receiving a phone call.')
    finally:
      # Ends the incoming phone call.
      sec_phone.sl4a.telecomEndCall()
      sec_phone.log.info('Ended the phone call.')
      is_idle = pri_phone.wait_for_call_state(
          bt_constants.CALL_STATE_IDLE,
          bt_constants.CALL_STATE_TIMEOUT_SEC)
      if not is_idle:
        raise signals.TestError(
            'Timed out after %ds waiting for the phone call to be ended.' %
            bt_constants.CALL_STATE_TIMEOUT_SEC)

    # Checks if A2DP audio is resumed.
    self.assert_a2dp_expected_status(
        is_playing=True,
        fail_msg='A2DP audio is not resumed when the phone call is ended.')

    # Starts audio capture for Bluetooth audio stream.
    self.derived_bt_device.start_audio_capture()

    # Stops audio capture and generates an recorded audio file.
    recorded_audio_file = self.derived_bt_device.stop_audio_capture()
    pri_phone.sl4a.mediaPlayStop()
    pri_phone.sl4a.mediaPlayClose()

    # Measures MOS for the recorded audio.
    mos = bt_audio_utils.measure_audio_mos(recorded_audio_file,
                                           self.reference_audio_file)

    # Asserts that the measured MOS should be more than the threshold.
    asserts.assert_true(
        mos >= self.threshold,
        'MOS of the recorded audio "%.3f" is lower than the threshold "%.3f".' %
        (mos, self.threshold))


if __name__ == '__main__':
  test_runner.main()
