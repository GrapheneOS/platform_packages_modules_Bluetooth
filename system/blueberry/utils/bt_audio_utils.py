# Lint as: python3
"""Utils for bluetooth audio testing."""

import logging as log
import os
import numpy as np
from scipy import signal as scipy_signal
from scipy.io import wavfile
# Internal import
# Internal import


def generate_sine_wave_to_device(
    device,
    pushed_file_path='/sdcard/Music',
    frequency=480,
    channel=2,
    sample_rate=48000,
    sample_format=16,
    duration_sec=10):
  """Generates a fixed frequency sine wave file and push it to the device.

  Generates a sine wave to the Mobly device directory and push it to the device
  storage. The output file name format is such as the example:
    sine_480hz_2ch_48000rate_16bit_10sec.wav

  Args:
    device: AndroidDevice, Mobly Android controller class.
    pushed_file_path: string, the wave file path which is pushed to the device
        storage. E.g. /sdcard/Music
    frequency: int, fixed frequency in Hz.
    channel: int, number of channels.
    sample_rate: int, sampling rate in Hz.
    sample_format: int, sampling format in bit.
    duration_sec: int, audio duration in second.

  Returns:
    device_storage_path: string, the wave file on the device storage.
    mobly_directory_path: string, the wave file on the Mobly device directory.
  """
  file_name = 'sine_%dhz_%dch_%drate_%dbit_%dsec.wav' % (
      frequency, channel, sample_rate, sample_format, duration_sec)
  mobly_directory_path = os.path.join(device.log_path, file_name)
  os.system('%s -n -c %d -r %d -b %d %s synth %d sine %d' %
            (audio_processor.AudioProcessor.SOX, channel, sample_rate,
             sample_format, mobly_directory_path, duration_sec, frequency))
  device.adb.push([mobly_directory_path, pushed_file_path])
  device_storage_path = os.path.join(pushed_file_path, file_name)
  return device_storage_path, mobly_directory_path


def measure_audio_mos(recorded_audio_file, reference_audio_file):
  """Measures mean opinion score (MOS) of a recorded audio.

  This function uses the module of A/V Analysis Service to measure MOS:
  Internal reference

  Args:
    recorded_audio_file: string, the recorded audio file to be measured.
    reference_audio_file: string, the reference audio file for comparison.

  Returns:
    Float which is the mean opinion score of the recorded audio.
  """
  results = audio_calculator.AudioAnalyzer().Analyze(reference_audio_file,
                                                     recorded_audio_file)
  # Returns 0.0 if the results fails to be generated.
  if not results:
    log.warning('Failed to generate the audio analysis results.')
    return 0.0
  return results[0].mos


def measure_fundamental_frequency(signal, sample_rate):
  """Measures fundamental frequency of a signal.

  Args:
    signal: An 1-D array representing the signal data.
    sample_rate: int, sample rate of the signal.

  Returns:
    Float representing the fundamental frequency.
  """
  return sample_rate * (np.argmax(np.abs(np.fft.rfft(signal))) / len(signal))


def measure_rms(signal):
  """Measures Root Mean Square (RMS) of a signal.

  Args:
    signal: An 1-D array representing the signal data.

  Returns:
    Float representing the root mean square.
  """
  return np.sqrt(np.mean(np.absolute(signal)**2))


def measure_thdn(signal, sample_rate, q, frequency=None):
  """Measures Total Harmonic Distortion + Noise (THD+N) of a signal.

  Args:
    signal: An 1-D array representing the signal data.
    sample_rate: int, sample rate of the signal.
    q: float, quality factor for the notch filter.
    frequency: float, fundamental frequency of the signal. All other frequencies
        are noise. If not specified, will be calculated using FFT.

  Returns:
    Float representing THD+N ratio calculated from the ratio of RMS of pure
        harmonics and noise signal to RMS of original signal.
  """
  # Normalizes the signal.
  signal -= np.mean(signal)
  # Gets Blackman-Harris window from the signal.
  window = signal * scipy_signal.blackmanharris(len(signal))
  # Finds the fundamental frequency to remove if not specified.
  if not frequency:
    frequency = measure_fundamental_frequency(window, sample_rate)
  # Creates a notch filter to get noise from the signal.
  wo = frequency / (sample_rate / 2)
  b, a = scipy_signal.iirnotch(wo, q)
  noise = scipy_signal.lfilter(b, a, window)
  return measure_rms(noise) / measure_rms(window)


def measure_audio_thdn_per_window(
    audio_file,
    thdn_threshold,
    step_size,
    window_size,
    q,
    frequency=None):
  """Measures Total Harmonic Distortion + Noise (THD+N) of an audio file.

  This function is used to capture audio glitches from a recorded audio file,
  and the audio file shall record a fixed frequency sine wave.

  Args:
    audio_file: A .wav file to be measured.
    thdn_threshold: float, a THD+N threshold used to compare with the measured
        THD+N for every windows. If THD+N of a window is greater than the
        threshold, will record this to results.
    step_size: int, number of samples to move the window by for each analysis.
    window_size: int, number of samples to analyze each time.
    q: float, quality factor for the notch filter.
    frequency: float, fundamental frequency of the signal. All other frequencies
        are noise. If not specified, will be calculated using FFT.

  Returns:
    List containing each result of channels. Like the following structure:
        ```
          [
              [  # result of channel 1
                  {
                      "thd+n": <float>,  # THD+N of a window
                      "start_time": <float>,  # start time of a window
                      "end_time": <float>,  # end time of a window
                  },
                  ...,
              ],
              [...,]  # result of channel 2
              ...,
          ]
        ```
  """
  if step_size <= 0:
    raise ValueError('step_size shall be greater than 0.')
  if window_size <= 0:
    raise ValueError('window_size shall be greater than 0.')
  sample_rate, wave_data = wavfile.read(audio_file)
  wave_data = wave_data.astype('float64')
  # Collects the result for each channels.
  results = []
  for signal in wave_data.transpose():
    current_position = 0
    channel_result = []
    while current_position + window_size < len(signal):
      window = signal[current_position:current_position + window_size]
      thdn = measure_thdn(
          signal=window,
          sample_rate=sample_rate,
          q=q,
          frequency=frequency)
      start_time = current_position / sample_rate
      end_time = (current_position + window_size) / sample_rate
      if thdn > thdn_threshold:
        channel_result.append({
            'thd+n': thdn,
            'start_time': start_time,
            'end_time': end_time
        })
      current_position += step_size
    results.append(channel_result)
  return results


def trim_audio(audio_file: str,
               duration_sec: float,
               start_time_sec: float = 0.0) -> str:
  """Trims an audio file with a specific start time and duration.

  Generates a output file and its name is such as below format:
    `<input file name>_<start time sec>-<duration sec>.<input file type>`

  Args:
    audio_file: string, an audio file to be trimed.
    duration_sec: float, the duration of the output file in seconds.
    start_time_sec: float, the start time of the audio file to be trimmed in
        seconds. Default value is 0.0 second if not specified.

  Returns:
    String, the output file of the same path of the origin file.
  """
  file_path, file_name = os.path.split(audio_file)
  file_name, file_ext = os.path.splitext(file_name)
  output_file_name = '%s_%s-%s%s' % (
      file_name,
      start_time_sec,
      (start_time_sec + duration_sec),
      file_ext)
  output_file = os.path.join(file_path, output_file_name)
  processor = audio_processor.AudioProcessor()
  processor.TrimAudio(
      input_file=audio_file,
      output_file=output_file,
      duration=duration_sec,
      start=start_time_sec)
  return output_file
