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

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProviders;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.floatingactionbutton.FloatingActionButton;

import com.android.bluetooth.leaudio.R;

public class BroadcasterActivity extends AppCompatActivity {
    private BroadcasterViewModel mViewModel;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.broadcaster_activity);

        FloatingActionButton fab = findViewById(R.id.broadcast_fab);
        fab.setOnClickListener(view -> {
            if (mViewModel.getBroadcastCount() < mViewModel.getMaximumNumberOfBroadcast()) {
                // Start Dialog with the broadcast input details
                AlertDialog.Builder alert = new AlertDialog.Builder(this);
                LayoutInflater inflater = getLayoutInflater();
                alert.setTitle("Add the Broadcast:");

                View alertView = inflater.inflate(R.layout.broadcaster_add_broadcast_dialog, null);
                final EditText code_input_text = alertView.findViewById(R.id.broadcast_code_input);
                EditText metadata_input_text = alertView.findViewById(R.id.broadcast_meta_input);

                alert.setView(alertView).setNegativeButton("Cancel", (dialog, which) -> {
                    // Do nothing
                }).setPositiveButton("Start", (dialog, which) -> {
                    if (mViewModel.startBroadcast(metadata_input_text.getText().toString(),
                            code_input_text.getText() == null
                                    || code_input_text.getText().length() == 0 ? null
                                            : code_input_text.getText().toString().getBytes()))
                        Toast.makeText(BroadcasterActivity.this, "Broadcast was created.",
                                Toast.LENGTH_SHORT).show();
                });

                alert.show();
            } else {
                Toast.makeText(BroadcasterActivity.this,
                        "Maximum number of broadcasts reached: " + Integer
                                .valueOf(mViewModel.getMaximumNumberOfBroadcast()).toString(),
                        Toast.LENGTH_SHORT).show();
            }
        });

        RecyclerView recyclerView = findViewById(R.id.broadcaster_recycle_view);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        recyclerView.setHasFixedSize(true);

        final BroadcastItemsAdapter itemsAdapter = new BroadcastItemsAdapter();
        itemsAdapter.setOnItemClickListener(broadcastId -> {
            AlertDialog.Builder alert = new AlertDialog.Builder(this);
            alert.setTitle("Broadcast actions:");

            alert.setNeutralButton("Stop", (dialog, which) -> {
                mViewModel.stopBroadcast(broadcastId);
            });
            alert.setPositiveButton("Modify", (dialog, which) -> {
                // Open activity for progam info
                AlertDialog.Builder modifyAlert = new AlertDialog.Builder(this);
                modifyAlert.setTitle("Modify the Broadcast:");

                LayoutInflater inflater = getLayoutInflater();
                View alertView = inflater.inflate(R.layout.broadcaster_add_broadcast_dialog, null);
                EditText metadata_input_text = alertView.findViewById(R.id.broadcast_meta_input);

                // The Code cannot be changed, so just hide it
                final EditText code_input_text = alertView.findViewById(R.id.broadcast_code_input);
                code_input_text.setVisibility(View.GONE);

                modifyAlert.setView(alertView)
                        .setNegativeButton("Cancel", (modifyDialog, modifyWhich) -> {
                            // Do nothing
                        }).setPositiveButton("Update", (modifyDialog, modifyWhich) -> {
                            if (mViewModel.updateBroadcast(broadcastId,
                                    metadata_input_text.getText().toString()))
                                Toast.makeText(BroadcasterActivity.this, "Broadcast was updated.",
                                        Toast.LENGTH_SHORT).show();
                        });

                modifyAlert.show();
            });

            alert.show();
            Log.d("CC", "Num broadcasts: " + mViewModel.getBroadcastCount());
        });
        recyclerView.setAdapter(itemsAdapter);

        // Get the initial state
        mViewModel = ViewModelProviders.of(this).get(BroadcasterViewModel.class);
        itemsAdapter.updateBroadcastsMetadata(mViewModel.getAllBroadcastMetadata());

        // Put a watch on updates
        mViewModel.getBroadcastUpdateMetadataLive().observe(this, audioBroadcast -> {
            itemsAdapter.updateBroadcastMetadata(audioBroadcast);

            Toast.makeText(BroadcasterActivity.this,
                    "Updated broadcast " + audioBroadcast.getBroadcastId(), Toast.LENGTH_SHORT)
                    .show();
        });

        // Put a watch on any error reports
        mViewModel.getBroadcastStatusMutableLive().observe(this, msg -> {
            Toast.makeText(BroadcasterActivity.this, msg, Toast.LENGTH_SHORT).show();
        });

        // Put a watch on broadcast playback states
        mViewModel.getBroadcastPlaybackStartedMutableLive().observe(this, reasonAndBidPair -> {
            Toast.makeText(BroadcasterActivity.this, "Playing broadcast " + reasonAndBidPair.second
                    + ", reason " + reasonAndBidPair.first, Toast.LENGTH_SHORT).show();

            itemsAdapter.updateBroadcastPlayback(reasonAndBidPair.second, true);
        });

        mViewModel.getBroadcastPlaybackStoppedMutableLive().observe(this, reasonAndBidPair -> {
            Toast.makeText(BroadcasterActivity.this, "Paused broadcast " + reasonAndBidPair.second
                    + ", reason " + reasonAndBidPair.first, Toast.LENGTH_SHORT).show();

            itemsAdapter.updateBroadcastPlayback(reasonAndBidPair.second, false);
        });

        mViewModel.getBroadcastAddedMutableLive().observe(this, broadcastId -> {
            itemsAdapter.addBroadcasts(broadcastId);

            Toast.makeText(BroadcasterActivity.this,
                    "Broadcast was added broadcastId: " + broadcastId, Toast.LENGTH_SHORT).show();
        });

        // Put a watch on broadcast removal
        mViewModel.getBroadcastRemovedMutableLive().observe(this, reasonAndBidPair -> {
            itemsAdapter.removeBroadcast(reasonAndBidPair.second);

            Toast.makeText(
                    BroadcasterActivity.this, "Broadcast was removed " + " broadcastId: "
                            + reasonAndBidPair.second + ", reason: " + reasonAndBidPair.first,
                    Toast.LENGTH_SHORT).show();
        });

        // Prevent destruction when loses focus
        this.setFinishOnTouchOutside(false);
    }

    @Override
    public void onBackPressed() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        startActivity(intent);
    }
}
