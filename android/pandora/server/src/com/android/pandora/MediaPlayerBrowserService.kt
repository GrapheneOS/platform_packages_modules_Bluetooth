/*
 * Copyright (C) 2022 The Android Open Source Project
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

package com.android.pandora

import android.content.Intent
import android.media.*
import android.media.browse.MediaBrowser.MediaItem
import android.media.session.*
import android.os.Bundle
import android.service.media.MediaBrowserService
import android.service.media.MediaBrowserService.BrowserRoot
import android.util.Log

/* MediaBrowserService to handle MediaButton and Browsing */
class MediaPlayerBrowserService : MediaBrowserService() {
  private val TAG = "PandoraMediaPlayerBrowserService"

  private lateinit var mediaSession: MediaSession
  private lateinit var playbackStateBuilder: PlaybackState.Builder
  private val mediaIdToChildren = mutableMapOf<String, MutableList<MediaItem>>()
  private var metadataItems = mutableMapOf<String, MediaMetadata>()
  private var queue = mutableListOf<MediaSession.QueueItem>()
  private var currentTrack = -1

  override fun onCreate() {
    super.onCreate()
    initBrowseFolderList()
    setupMediaSession()
    instance = this
  }

  private fun setupMediaSession() {
    mediaSession = MediaSession(this, "MediaSession")

    mediaSession.setFlags(
      MediaSession.FLAG_HANDLES_MEDIA_BUTTONS or MediaSession.FLAG_HANDLES_TRANSPORT_CONTROLS
    )
    mediaSession.setCallback(mSessionCallback)
    initQueue()
    mediaSession.setQueue(queue)
    playbackStateBuilder =
      PlaybackState.Builder()
        .setState(PlaybackState.STATE_NONE, 0, 1.0f)
        .setActions(getAvailableActions())
        .setActiveQueueItemId(QUEUE_START_INDEX.toLong())
    mediaSession.setPlaybackState(playbackStateBuilder.build())
    mediaSession.setMetadata(null)
    mediaSession.setQueueTitle(NOW_PLAYING_PREFIX)
    mediaSession.isActive = true
    sessionToken = mediaSession.sessionToken
  }

  private fun getAvailableActions(): Long =
    PlaybackState.ACTION_SKIP_TO_PREVIOUS or
      PlaybackState.ACTION_SKIP_TO_NEXT or
      PlaybackState.ACTION_FAST_FORWARD or
      PlaybackState.ACTION_REWIND or
      PlaybackState.ACTION_PLAY or
      PlaybackState.ACTION_STOP or
      PlaybackState.ACTION_PAUSE

  private fun setPlaybackState(state: Int) {
    playbackStateBuilder.setState(state, 0, 1.0f).setActiveQueueItemId(currentTrack.toLong())
    mediaSession.setPlaybackState(playbackStateBuilder.build())
  }

  fun play() {
    if (currentTrack == -1 || currentTrack == QUEUE_SIZE) currentTrack = QUEUE_START_INDEX
    else currentTrack += 1
    setPlaybackState(PlaybackState.STATE_PLAYING)
    mediaSession.setMetadata(metadataItems.get("" + currentTrack))
  }

  fun stop() {
    setPlaybackState(PlaybackState.STATE_STOPPED)
    mediaSession.setMetadata(null)
  }

  fun pause() {
    setPlaybackState(PlaybackState.STATE_PAUSED)
  }

  fun rewind() {
    setPlaybackState(PlaybackState.STATE_REWINDING)
  }

  fun fastForward() {
    setPlaybackState(PlaybackState.STATE_FAST_FORWARDING)
  }

  fun forward() {
    if (currentTrack == QUEUE_SIZE || currentTrack == -1) currentTrack = QUEUE_START_INDEX
    else currentTrack += 1
    setPlaybackState(PlaybackState.STATE_SKIPPING_TO_NEXT)
    mediaSession.setMetadata(metadataItems.get("" + currentTrack))
    setPlaybackState(PlaybackState.STATE_PLAYING)
  }

  fun backward() {
    if (currentTrack == QUEUE_START_INDEX || currentTrack == -1) currentTrack = QUEUE_SIZE
    else currentTrack -= 1
    setPlaybackState(PlaybackState.STATE_SKIPPING_TO_PREVIOUS)
    mediaSession.setMetadata(metadataItems.get("" + currentTrack))
    setPlaybackState(PlaybackState.STATE_PLAYING)
  }

  fun setLargeMetadata() {
    currentTrack = QUEUE_SIZE
    mediaSession.setMetadata(metadataItems.get("" + currentTrack))
    setPlaybackState(PlaybackState.STATE_PLAYING)
  }

  fun updateQueue() {
    val metaData: MediaMetadata =
      MediaMetadata.Builder()
        .putString(MediaMetadata.METADATA_KEY_MEDIA_ID, NOW_PLAYING_PREFIX + NEW_QUEUE_ITEM_INDEX)
        .putString(MediaMetadata.METADATA_KEY_TITLE, "Title" + NEW_QUEUE_ITEM_INDEX)
        .putString(MediaMetadata.METADATA_KEY_ARTIST, "Artist" + NEW_QUEUE_ITEM_INDEX)
        .putString(MediaMetadata.METADATA_KEY_ALBUM, "Album" + NEW_QUEUE_ITEM_INDEX)
        .putLong(MediaMetadata.METADATA_KEY_TRACK_NUMBER, NEW_QUEUE_ITEM_INDEX.toLong())
        .putLong(MediaMetadata.METADATA_KEY_NUM_TRACKS, NEW_QUEUE_ITEM_INDEX.toLong())
        .build()
    val mediaItem = MediaItem(metaData.description, MediaItem.FLAG_PLAYABLE)
    queue.add(MediaSession.QueueItem(mediaItem.description, NEW_QUEUE_ITEM_INDEX.toLong()))
    mediaSession.setQueue(queue)
  }

  private val mSessionCallback: MediaSession.Callback =
    object : MediaSession.Callback() {
      override fun onPlay() {
        Log.i(TAG, "onPlay")
        play()
      }

      override fun onPause() {
        Log.i(TAG, "onPause")
        pause()
      }

      override fun onSkipToPrevious() {
        Log.i(TAG, "onSkipToPrevious")
        // TODO : Need to handle to play previous audio in the list
      }

      override fun onSkipToNext() {
        Log.i(TAG, "onSkipToNext")
        // TODO : Need to handle to play next audio in the list
      }

      override fun onMediaButtonEvent(mediaButtonEvent: Intent): Boolean {
        Log.i(TAG, "MediaSessionCallback——》onMediaButtonEvent $mediaButtonEvent")
        return super.onMediaButtonEvent(mediaButtonEvent)
      }
    }

  override fun onGetRoot(p0: String, clientUid: Int, rootHints: Bundle?): BrowserRoot? {
    Log.i(TAG, "onGetRoot")
    return BrowserRoot(ROOT, null)
  }

  override fun onLoadChildren(parentId: String, result: Result<MutableList<MediaItem>>) {
    Log.i(TAG, "onLoadChildren")
    if (parentId == ROOT) {
      val map = mediaIdToChildren[ROOT]
      Log.i(TAG, "onloadchildren $map")
      result.sendResult(map)
    } else if (parentId == NOW_PLAYING_PREFIX) {
      result.sendResult(mediaIdToChildren[NOW_PLAYING_PREFIX])
    } else {
      Log.i(TAG, "onloadchildren inside else")
      result.sendResult(null)
    }
  }

  private fun initMediaItems() {
    var mediaItems = mutableListOf<MediaItem>()
    for (item in QUEUE_START_INDEX..QUEUE_SIZE) {
      val metaData: MediaMetadata =
        MediaMetadata.Builder()
          .putString(MediaMetadata.METADATA_KEY_MEDIA_ID, NOW_PLAYING_PREFIX + item)
          .putString(MediaMetadata.METADATA_KEY_TITLE, "Title$item")
          .putString(
            MediaMetadata.METADATA_KEY_ARTIST,
            if (item != QUEUE_SIZE) "Artist$item" else generateAlphanumericString(512)
          )
          .putString(
            MediaMetadata.METADATA_KEY_ALBUM,
            if (item != QUEUE_SIZE) "Album$item" else generateAlphanumericString(512)
          )
          .putLong(MediaMetadata.METADATA_KEY_TRACK_NUMBER, item.toLong())
          .putLong(MediaMetadata.METADATA_KEY_NUM_TRACKS, QUEUE_SIZE.toLong())
          .build()
      val mediaItem = MediaItem(metaData.description, MediaItem.FLAG_PLAYABLE)
      mediaItems.add(mediaItem)
      metadataItems.put("" + item, metaData)
    }
    mediaIdToChildren[NOW_PLAYING_PREFIX] = mediaItems
  }

  private fun initQueue() {
    for ((key, value) in metadataItems.entries) {
      val mediaItem = MediaItem(value.description, MediaItem.FLAG_PLAYABLE)
      queue.add(MediaSession.QueueItem(mediaItem.description, key.toLong()))
    }
  }

  private fun initBrowseFolderList() {
    var rootList = mediaIdToChildren[ROOT] ?: mutableListOf()

    val emptyFolderMetaData =
      MediaMetadata.Builder()
        .putString(MediaMetadata.METADATA_KEY_MEDIA_ID, EMPTY_FOLDER)
        .putString(MediaMetadata.METADATA_KEY_TITLE, EMPTY_FOLDER)
        .putLong(
          MediaMetadata.METADATA_KEY_BT_FOLDER_TYPE,
          MediaDescription.BT_FOLDER_TYPE_PLAYLISTS
        )
        .build()
    val emptyFolderMediaItem = MediaItem(emptyFolderMetaData.description, MediaItem.FLAG_BROWSABLE)

    val playlistMetaData =
      MediaMetadata.Builder()
        .apply {
          putString(MediaMetadata.METADATA_KEY_MEDIA_ID, NOW_PLAYING_PREFIX)
          putString(MediaMetadata.METADATA_KEY_TITLE, NOW_PLAYING_PREFIX)
          putLong(
            MediaMetadata.METADATA_KEY_BT_FOLDER_TYPE,
            MediaDescription.BT_FOLDER_TYPE_PLAYLISTS
          )
        }
        .build()

    val playlistsMediaItem = MediaItem(playlistMetaData.description, MediaItem.FLAG_BROWSABLE)

    rootList += emptyFolderMediaItem
    rootList += playlistsMediaItem
    mediaIdToChildren[ROOT] = rootList
    initMediaItems()
  }

  companion object {
    lateinit var instance: MediaPlayerBrowserService
    const val ROOT = "__ROOT__"
    const val EMPTY_FOLDER = "@empty@"
    const val NOW_PLAYING_PREFIX = "NowPlayingId"
    const val QUEUE_START_INDEX = 1
    const val QUEUE_SIZE = 6
    const val NEW_QUEUE_ITEM_INDEX = 7

    fun isInitialized(): Boolean = this::instance.isInitialized
  }
}
