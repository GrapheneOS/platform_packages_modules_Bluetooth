/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

package com.android.bluetooth.leaudio;

import android.bluetooth.BluetoothLeBroadcastMetadata;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.cardview.widget.CardView;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.android.bluetooth.leaudio.R;

public class BroadcastItemsAdapter
        extends RecyclerView.Adapter<BroadcastItemsAdapter.BroadcastItemHolder> {
    private List<BluetoothLeBroadcastMetadata> mBroadcastMetadata = new ArrayList<>();
    private final Map<Integer /* broadcastId */, Boolean /* isPlaying */> mBroadcastPlayback =
            new HashMap<>();
    private OnItemClickListener mOnItemClickListener;

    @NonNull
    @Override
    public BroadcastItemHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View item_view = LayoutInflater.from(parent.getContext()).inflate(R.layout.broadcast_item,
                parent, false);
        return new BroadcastItemHolder(item_view, mOnItemClickListener);
    }

    public void setOnItemClickListener(OnItemClickListener listener) {
        this.mOnItemClickListener = listener;
    }

    @Override
    public void onBindViewHolder(@NonNull BroadcastItemHolder holder, int position) {
        Integer broadcastId = (Integer) mBroadcastPlayback.keySet().toArray()[position];
        Boolean isPlaying = mBroadcastPlayback.get(broadcastId);

        // Set card color based on the playback state
        if (isPlaying) {
            holder.background
                    .setCardBackgroundColor(ColorStateList.valueOf(Color.parseColor("#92b141")));
            holder.mTextViewBroadcastId.setText("ID: " + broadcastId + " ▶️");
        } else {
            holder.background.setCardBackgroundColor(ColorStateList.valueOf(Color.WHITE));
            holder.mTextViewBroadcastId.setText("ID: " + broadcastId + " ⏸");
        }

        // TODO: Add additional informations to the card
        // BluetoothLeBroadcastMetadata current_item = mBroadcastMetadata.get(position);
    }

    @Override
    public int getItemCount() {
        return mBroadcastPlayback.size();
    }

    public void updateBroadcastsMetadata(List<BluetoothLeBroadcastMetadata> broadcasts) {
        mBroadcastMetadata = broadcasts;
        notifyDataSetChanged();
    }

    public void updateBroadcastMetadata(BluetoothLeBroadcastMetadata broadcast) {
        mBroadcastMetadata.removeIf(bc -> (bc.getBroadcastId() == broadcast.getBroadcastId()));
        mBroadcastMetadata.add(broadcast);
        notifyDataSetChanged();
    }

    public void addBroadcasts(Integer broadcastId) {
        if (!mBroadcastPlayback.containsKey(broadcastId))
            mBroadcastPlayback.put(broadcastId, false);
    }

    public void removeBroadcast(Integer broadcastId) {
        mBroadcastMetadata.removeIf(bc -> (broadcastId.equals(bc.getBroadcastId())));
        mBroadcastPlayback.remove(broadcastId);
        notifyDataSetChanged();
    }

    public void updateBroadcastPlayback(Integer broadcastId, boolean isPlaying) {
        mBroadcastPlayback.put(broadcastId, isPlaying);
        notifyDataSetChanged();
    }

    public interface OnItemClickListener {
        void onItemClick(Integer broadcastId);
    }

    class BroadcastItemHolder extends RecyclerView.ViewHolder {
        private final TextView mTextViewBroadcastId;
        private final CardView background;

        public BroadcastItemHolder(@NonNull View itemView, OnItemClickListener listener) {
            super(itemView);

            mTextViewBroadcastId = itemView.findViewById(R.id.broadcast_id_text);
            background = itemView.findViewById(R.id.broadcast_item_card_view);

            itemView.setOnClickListener(v -> {
                if (listener == null) return;

                int position = getAdapterPosition();
                if (position != RecyclerView.NO_POSITION) {
                    Integer broadcastId = (Integer) mBroadcastPlayback.keySet().toArray()[position];
                    listener.onItemClick(broadcastId);
                }
            });
        }
    }
}
