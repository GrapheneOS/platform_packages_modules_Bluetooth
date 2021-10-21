/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 */
package com.android.bluetooth.bc;

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Iterator;
import android.os.Message;
import android.util.Log;
import java.util.UUID;
import java.util.Collection;
import android.os.UserHandle;

import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Scanner;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.lang.String;
import java.lang.StringBuffer;
import java.lang.Integer;

import java.nio.ByteBuffer;
import java.lang.Byte;
import java.util.stream.IntStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.BleBroadcastSourceChannel;
///*_BMS
import com.android.bluetooth.broadcast.BroadcastService.BisInfo;
import com.android.bluetooth.broadcast.BroadcastService.MetadataLtv;
//_BMS*/

/**
 * Helper class to parase the Broadcast Announcement BASE data
 */
final class BaseData {
            private static final String TAG = "Bassclient-BaseData";
            BaseInformation levelOne = new BaseInformation();
            ArrayList<BaseInformation> levelTwo = new ArrayList<BaseInformation>();
            ArrayList<BaseInformation> levelThree = new ArrayList<BaseInformation>();
            int mNumBISIndicies;
            public static byte UNKNOWN_CODEC = (byte)0xFE;

            public class BaseInformation {
            public byte[] presentationDelay = new byte[3];    //valid only if level=1
            public byte[] codecId = new byte[5]; //valid only if level=1
            public byte codecConfigLength;
            public byte[] codecConfigInfo;
            public byte metaDataLength;
            public byte[] metaData;
            public byte numSubGroups;
            public byte[] bisIndicies; //valid only if level = 2
            public byte index; //valid only if level=3 and level=2 (as subgroup Id)
            public int subGroupId;
            public int level;//differentiate different levels of BASE data
            public LinkedHashSet<String> keyCodecCfgDiff;
            public LinkedHashSet<String> keyMetadataDiff;
            public String diffText;
            public String description;

            public byte[] consolidatedCodecId;
            public Set<String> consolidatedMetadata;
            public Set<String> consolidatedCodecInfo;
            public HashMap<Integer, String> consolidatedUniqueCodecInfo;
            public HashMap<Integer, String> consolidatedUniqueMetadata;

            BaseInformation() {
             presentationDelay = new byte[3];
             codecId = new byte[5];
             codecConfigLength = 0;
             codecConfigInfo = null;
             metaDataLength = 0;
             metaData = null;
             numSubGroups = 0;
             bisIndicies = null;
             index = (byte)0xFF;
             level = 0;

             keyCodecCfgDiff = new LinkedHashSet<String>();
             keyMetadataDiff = new LinkedHashSet<String>();

             consolidatedMetadata = new LinkedHashSet<String>();
             consolidatedCodecInfo = new LinkedHashSet<String>();
             consolidatedCodecId = new byte[5];
             consolidatedUniqueMetadata = new HashMap<Integer, String>();
             consolidatedUniqueCodecInfo = new HashMap<Integer, String>();
             diffText = new String("");
             description = new String("");
             log("BaseInformation is Initialized");
            }

            boolean isCodecIdUnknown() {
                return (codecId != null && codecId[4] == (byte)BaseData.UNKNOWN_CODEC);
            }

            void printConsolidated() {
                    log("**BEGIN: BIS consolidated Information**");
                    log("BIS index:" + index);
                    log("CodecId:" + Arrays.toString(consolidatedCodecId));

                    /*if (consolidatedCodecInfo != null) {
                        Iterator<String> itr = consolidatedCodecInfo.iterator();
                        for (int k=0; itr.hasNext(); k++) {
                            log("consolidatedCodecInfo:[" + k + "]:" + Arrays.toString(itr.next().getBytes()));
                        }
                    }

                    if (consolidatedMetadata != null) {
                        Iterator<String> itr = consolidatedMetadata.iterator();
                        for (int k=0; itr.hasNext(); k++) {
                            log("consolidatedMetadata:[" + k + "]:" + Arrays.toString(itr.next().getBytes()));
                        }
                    }*/

                    if (consolidatedUniqueCodecInfo != null) {
                        for (Map.Entry<Integer,String> entry : consolidatedUniqueCodecInfo.entrySet()) {
                            log("consolidatedUniqueCodecInfo:[" + entry.getKey() + "]:" + Arrays.toString(entry.getValue().getBytes()));
                        }
                    }

                    if (consolidatedUniqueMetadata != null) {
                        for (Map.Entry<Integer,String> entry : consolidatedUniqueMetadata.entrySet()) {
                            log("consolidatedUniqueMetadata:[" + entry.getKey() + "]:" + Arrays.toString(entry.getValue().getBytes()));
                        }
                    }
                    log("**END: BIS consolidated Information****");
            }
            void print() {
                log("**BEGIN: Base Information**");
                log("**Level: " + level + "***");
                if (level == 1) {
                    log("presentationDelay: " + Arrays.toString(presentationDelay));
                }
                if (level == 2) {
                    log("codecId: " + Arrays.toString(codecId));
                }
                if (level == 2 || level == 3) {
                    log("codecConfigLength: " + codecConfigLength);
                    log("subGroupId: " + subGroupId);
                }
                if (codecConfigLength != (byte)0) {
                    log("codecConfigInfo: " + Arrays.toString(codecConfigInfo));
                }
                if (level == 2) {
                    log("metaDataLength: " + metaDataLength);
                    if (metaDataLength != (byte)0) {
                        log("metaData: " + Arrays.toString(metaData));
                    }
                if (level == 1 || level == 2)
                    log("numSubGroups: " + numSubGroups);
                }
                if (level == 2) {
                    log("Level2: Key Metadata differentiators");
                    if (keyMetadataDiff != null) {
                        Iterator<String> itr = keyMetadataDiff.iterator();
                        for (int k=0; itr.hasNext(); k++) {
                            log("keyMetadataDiff:[" + k + "]:" + Arrays.toString(itr.next().getBytes()));
                        }
                    }
                    log("END: Level2: Key Metadata differentiators");

                    log("Level2: Key CodecConfig differentiators");
                    if (keyCodecCfgDiff != null) {
                        Iterator<String> itr = keyCodecCfgDiff.iterator();
                        for (int k=0; itr.hasNext(); k++) {
                            log("LEVEL2: keyCodecCfgDiff:[" + k + "]:" + Arrays.toString(itr.next().getBytes()));
                        }
                    }
                    log("END: Level2: Key CodecConfig differentiators");
                    //log("bisIndicies: " + Arrays.toString(bisIndicies));
                    log("LEVEL2: diffText: " + diffText);
                }
                if (level == 3) {
                    log("Level3: Key CodecConfig differentiators");
                    if (keyCodecCfgDiff != null) {
                        Iterator<String> itr = keyCodecCfgDiff.iterator();
                        for (int k=0; itr.hasNext(); k++) {
                            log("LEVEL3: keyCodecCfgDiff:[" + k + "]:" + Arrays.toString(itr.next().getBytes()));
                        }
                    }
                    log("END: Level3: Key CodecConfig differentiators");
                    log("index: " + index);
                    log("LEVEL3: diffText: " + diffText);
                }
                log("**END: Base Information****");
            }
        };
            ///*_BMS
            BaseData(int numSubGroups, List<BisInfo> colocatedBisInfo, Map<Integer, MetadataLtv> metaInfo) {
                if (metaInfo == null || colocatedBisInfo == null) {

                    Log.e(TAG, "BaseData Contruction with Invalid parameters");
                    throw new IllegalArgumentException("Basedata: Parameters can't be null");
                }
                levelOne = new BaseInformation();
                levelTwo = new ArrayList<BaseInformation>();
                levelThree = new ArrayList<BaseInformation>();

                levelOne.level = 1;
                levelOne.numSubGroups = (byte)numSubGroups;

                //create the level Two and update the Metadata Info
                for (int i=0; i<numSubGroups; i++) {
                    BaseInformation a = new BaseInformation();
                    a.level = 2;
                    //get Metadata Ltv
                    byte[] metadataLtv = null;
                    if (metaInfo != null) {
                        Log.d(TAG, "metaInfo: " + metaInfo);
                        MetadataLtv obj = metaInfo.get(i);
                        if (obj != null) {
                            metadataLtv = obj.getByteArray();
                            Log.d(TAG, "metadataLtv: " + metadataLtv);
                        } else {
                            Log.d(TAG, "metadataLtv[" +i+"] is not available");
                        }
                    }
                    if (metadataLtv != null) {
                        a.metaData = new byte[(int)metadataLtv.length];
                        System.arraycopy(metadataLtv, 0, a.metaData, 0, (int)metadataLtv.length);
                    }
                    levelTwo.add(a);
                }

                if (colocatedBisInfo != null) {
                    mNumBISIndicies = colocatedBisInfo.size();
                    for (int i = 0; i < colocatedBisInfo.size(); i++) {
                        BisInfo bisInfo = colocatedBisInfo.get(i);
                        BaseInformation b = new BaseInformation();
                        b.level = 3;
                        b.subGroupId = bisInfo.mSubGroupId;
                        b.index = (byte)bisInfo.BisIndex;

                        b.consolidatedCodecId = bisInfo.mCodecId;

                        //get Metadata Ltv
                        byte[] metadataLtv = bisInfo.BisMetadata.getByteArray();
                        if (metadataLtv != null) {
                            int k = 0;
                            while (k<metadataLtv.length) {
                                byte length = metadataLtv[k++];
                                byte[] ltv = new byte[length+1];
                                ltv[0] = length;
                                System.arraycopy(metadataLtv, k, ltv, 1, length);
                                //put in type, ltv hashmap
                                String s = new String(ltv);
                                b.consolidatedUniqueMetadata.put((int)ltv[1], s);
                                log("add Metadata:::");
                                k = k+length;
                            }
                        }

                        //get CodecConfig ltv
                        byte[] codecConfigLtv = bisInfo.BisCodecConfig.getByteArray();
                        if (codecConfigLtv != null) {
                            int k = 0;
                            while (k<codecConfigLtv.length) {
                                byte length = codecConfigLtv[k++];
                                byte[] ltv = new byte[length+1];
                                ltv[0] = length;
                                System.arraycopy(codecConfigLtv, k, ltv, 1, length);
                                //put in type, ltv hashmap
                                String s = new String(ltv);
                                b.consolidatedUniqueCodecInfo.put((int)ltv[1], s);
                                log("add CodecConfig entry:::");
                                k = k+length;
                            }
                        }
                        //update description with "Chennel: X"
                        b.description = "Channel: " + String.valueOf(b.index);
                        levelThree.add(b);
                      }
                }
            }
            //_BMS*/
            BaseData(byte[] serviceData) {
                if (serviceData == null) {
                    Log.e(TAG, "Invalid service data for BaseData construction");
                    throw new IllegalArgumentException("Basedata: serviceData is null");
                }
                levelOne = new BaseInformation();
                levelTwo = new ArrayList<BaseInformation>();
                levelThree = new ArrayList<BaseInformation>();
                mNumBISIndicies = 0;
                log("members initialized");
                log("BASE input" + Arrays.toString(serviceData));

                //Parse Level 1 base
                levelOne.level = 1;
                int level1Idx = 0;
                System.arraycopy(serviceData, level1Idx, levelOne.presentationDelay,0, 3);
                level1Idx = level1Idx + 3;

                levelOne.numSubGroups = serviceData[level1Idx++];
                levelOne.print();
                log("levelOne subgroups" + levelOne.numSubGroups);

                int level2Idx = level1Idx;
                for (int i =0; i<(int)levelOne.numSubGroups; i++) {
                    log("parsing subgroup" + i);
                    BaseInformation b = new BaseInformation();

                    b.level = 2;
                    b.subGroupId = i;
                    b.numSubGroups = serviceData[level2Idx++];
                    if (serviceData[level2Idx] == (byte)UNKNOWN_CODEC) {
                        //Place It in the last byte of codecID
                        System.arraycopy(serviceData, level2Idx, b.codecId, 4, 1);
                        level2Idx =  level2Idx + 1;
                        log("codecId is FE");
                    } else {
                        System.arraycopy(serviceData, level2Idx, b.codecId, 0, 5);
                        level2Idx =  level2Idx + 5;
                    }

                    b.codecConfigLength =  serviceData[level2Idx++];
                    if (b.codecConfigLength != 0) {
                        b.codecConfigInfo = new byte[(int)b.codecConfigLength];
                        System.arraycopy(serviceData, level2Idx, b.codecConfigInfo, 0, (int)b.codecConfigLength);
                        level2Idx = level2Idx + (int)b.codecConfigLength;
                    }
                    b.metaDataLength = serviceData[level2Idx++];
                    if (b.metaDataLength != 0) {
                        b.metaData = new byte[(int)b.metaDataLength];
                        System.arraycopy(serviceData, level2Idx, b.metaData, 0, (int)b.metaDataLength);
                        level2Idx = level2Idx + (int)b.metaDataLength;
                    }
                    mNumBISIndicies = mNumBISIndicies + b.numSubGroups;
                    levelTwo.add(b);
                    b.print();
                }
                //Parse Level 3 Base
                int level3Index = level2Idx;
                for (int k=0; k<mNumBISIndicies; k++) {
                    BaseInformation c = new BaseInformation();
                    c.level = 3;
                    c.index = serviceData[level3Index++];

                    c.codecConfigLength =  serviceData[level3Index++];
                    if (c.codecConfigLength != 0) {
                        c.codecConfigInfo = new byte[(int)c.codecConfigLength];
                        System.arraycopy(serviceData, level3Index, c.codecConfigInfo, 0, (int)c.codecConfigLength);
                        level3Index = level3Index + (int)c.codecConfigLength;
                   }
                   levelThree.add(c);
                }

                consolidateBaseofLevelTwo();

                //Detailed BASE parsing below
                //log("calling updateUniquenessForLevelTwo");
                //updateUniquenessForLevelTwo(levelOne.numSubGroups);
                //updateDiffTextforNodes();
            }

                void consolidateBaseofLevelTwo() {
                    int startIdx = 0;
                    int children = 0;

                    for (int i=0; i<levelTwo.size(); i++) {
                        startIdx = startIdx+ children;
                        children = children + levelTwo.get(i).numSubGroups;

                        consolidateBaseofLevelThree(i, startIdx, levelTwo.get(i).numSubGroups);
                    }

                    //Eliminate Duplicates at Level 3
                    for (int i=0; i<levelThree.size(); i++) {
                        Map<Integer, String> uniqueMds = new HashMap<Integer, String> ();
                        Map<Integer, String> uniqueCcis = new HashMap<Integer, String> ();

                        Set<String> Csfs = levelThree.get(i).consolidatedCodecInfo;

                        if (Csfs.size() > 0) {
                            Iterator<String> itr = Csfs.iterator();
                            for (int j=0; itr.hasNext(); j++) {
                                byte[] ltvEntries = itr.next().getBytes();

                                int k = 0;
                                byte length = ltvEntries[k++];
                                byte[] ltv = new byte[length+1];
                                ltv[0] = length;
                                System.arraycopy(ltvEntries, k, ltv, 1, length);

                                //
                                int type = (int)ltv[1];
                                String s = uniqueCcis.get(type);
                                String ltvS = new String(ltv);
                                if (s == null) {
                                    uniqueCcis.put(type, ltvS);
                                } else {
                                    //if same type exists
                                    //replace
                                    uniqueCcis.replace(type, ltvS);
                                }
                            }
                        }

                        Set<String> Mds = levelThree.get(i).consolidatedMetadata;
                        if (Mds.size() > 0) {
                            Iterator<String> itr = Mds.iterator();
                            for (int j=0; itr.hasNext(); j++) {
                                byte[] ltvEntries = itr.next().getBytes();

                                int k = 0;
                                byte length = ltvEntries[k++];
                                byte[] ltv = new byte[length+1];
                                ltv[0] = length;
                                System.arraycopy(ltvEntries, k, ltv, 1, length);

                                /*CHECK: This can be straight PUT, there wont be dups in Metadata with new BASE*/
                                int type = (int)ltv[1];
                                String s = uniqueCcis.get(type);
                                String ltvS = new String(ltv);
                                if (s == null) {
                                    uniqueMds.put(type, ltvS);
                                } else {
                                    //if same type exists
                                    //replace
                                    uniqueMds.replace(type, ltvS);
                                }
                            }
                        }

                        levelThree.get(i).consolidatedUniqueMetadata = new HashMap<Integer, String>(uniqueMds);
                        levelThree.get(i).consolidatedUniqueCodecInfo = new HashMap<Integer, String>(uniqueCcis);

                }
             }

                void consolidateBaseofLevelThree(int parentSubgroup, int startIdx, int numNodes) {

                    for (int i=startIdx; i<startIdx+numNodes||i<levelThree.size(); i++) {

                        levelThree.get(i).subGroupId = levelTwo.get(parentSubgroup).subGroupId;

                        log("Copy Codec Id from Level2 Parent" + parentSubgroup);
                        System.arraycopy(levelTwo.get(parentSubgroup).consolidatedCodecId,
                                              0 ,levelThree.get(i).consolidatedCodecId, 0, 5);

                        //Metadata clone from Parent
                        levelThree.get(i).consolidatedMetadata = new LinkedHashSet<String>(levelTwo.get(parentSubgroup).consolidatedMetadata);

                        //log("Parent Cons Info>>");
                        //levelTwo.get(parentSubgroup).printConsolidated();
                        //CCI clone from Parent
                        levelThree.get(i).consolidatedCodecInfo = new LinkedHashSet<String>(levelTwo.get(parentSubgroup).consolidatedCodecInfo);
                        //log("before " + i);
                        //levelThree.get(i).printConsolidated();
                        //Append Level 2 Codec Config
                        if (levelThree.get(i).codecConfigLength != 0) {
                            log("append level 3 cci to level 3 cons:" + i);
                            String s = new String(levelThree.get(i).codecConfigInfo);
                            levelThree.get(i).consolidatedCodecInfo.add(s);
                        }
                        //log("after " + i);
                        //levelThree.get(i).printConsolidated();
                        //log("Parent Cons Info>>");
                        //levelTwo.get(parentSubgroup).printConsolidated();
                    }

                }

                public int getNumberOfIndicies() {
                    return mNumBISIndicies;
                }

                public byte getNumberOfSubgroupsofBIG() {
                    byte ret = 0;
                    if (levelOne != null) {
                        ret = levelOne.numSubGroups;
                    }
                    return ret;
                }

                public  ArrayList<BaseInformation> getBISIndexInfos() {
                    return levelThree;
                }
                List<BleBroadcastSourceChannel>  getBroadcastChannels() {
                    List<BleBroadcastSourceChannel> bChannels = new ArrayList<BleBroadcastSourceChannel>();
                    for (int k=0; k<mNumBISIndicies; k++) {
                        int index = levelThree.get(k).index;
                        String desc = levelThree.get(k).description;
                        //String desc = String.valueOf(index);
                        BleBroadcastSourceChannel bc = new BleBroadcastSourceChannel(index, desc, false,
                                             levelThree.get(k).subGroupId, levelThree.get(k).metaData);
                        bChannels.add(bc);
                    }
                    return bChannels;
                }

                List<BleBroadcastSourceChannel> pickAllBroadcastChannels() {
                    List<BleBroadcastSourceChannel> bChannels = new ArrayList<BleBroadcastSourceChannel>();
                    for (int k=0; k<mNumBISIndicies; k++) {
                        int index = levelThree.get(k).index;
                        //String desc = levelThree.get(k).description;
                        //String desc = String.valueOf(index);
                        BleBroadcastSourceChannel bc = new BleBroadcastSourceChannel(index, String.valueOf(index), true,
                                                               levelThree.get(k).subGroupId, levelThree.get(k).metaData);
                        bChannels.add(bc);
                    }
                    return bChannels;
                }
                byte[] getMetadata(int subGroup) {
                    if (levelTwo != null) {
                        return levelTwo.get(subGroup).metaData;
                    }
                    return null;
                }

                String getMetadataString(byte[] metadataBytes) {
                    final int _LANGUAGE = 0;
                        //Different language
                        final int _ENGLISH = 1;
                        final int _SPANISH = 2;
                    final int _DESCRIPTION = 1;
                    String ret = new String();

                    switch(metadataBytes[1]) {
                        case _LANGUAGE:
                            switch (metadataBytes[2]) {
                                case _ENGLISH:
                                    ret = "ENGLISH"; break;
                                case _SPANISH:
                                    ret = "SPANISH"; break;
                                default:
                                    ret = "UNKNOWN"; break;
                            }
                            break;
                        case _DESCRIPTION:
                            ret = "UNKNOWN";
                            break;
                        default:
                            ret = "UNKNOWN";
                    }
                    log("getMetadataString: " + ret);
                    return ret;
                }

                String getCodecParamString(byte[] csiBytes) {
                    final  int LOCATION = 4;
                    final  int LEFT = 0x01000000;
                    final  int RIGHT =0x02000000;
                    String ret = new String();

                    //sample rate
                    final int SAMPLE_RATE = 1;

                    //frame duration
                    final int FRAME_DURATION = 2;

                    //Octets per frame
                    final int OCTETS_PER_FRAME = 8;
                    switch(csiBytes[1]) {
                        case LOCATION:
                            byte[] location = new byte[4];
                            System.arraycopy(csiBytes, 2, location, 0, 4);
                            ByteBuffer wrapped = ByteBuffer.wrap(location);
                            int audioLocation = wrapped.getInt();
                            log("audioLocation: " + audioLocation);

                            switch (audioLocation) {
                                case LEFT: ret = "LEFT"; break;
                                case RIGHT: ret = "RIGHT"; break;
                                case LEFT|RIGHT: ret = "LR"; break;
                            }
                            break;
                        case SAMPLE_RATE:
                            switch(csiBytes[2]) {
                                    case 1:
                                        ret = "8K"; break;
                                    case 2:
                                        ret = "16K"; break;
                                    case 3:
                                        ret = "24K"; break;
                                    case 4:
                                        ret = "32K"; break;
                                    case 5:
                                        ret = "44.1K"; break;
                                    case 6:
                                        ret = "48K"; break;
                            }
                            break;
                        case FRAME_DURATION:
                            switch(csiBytes[2]) {
                                    case 1:
                                        ret = "FD_1"; break;
                            }
                            break;
                        case OCTETS_PER_FRAME:
                            switch(csiBytes[2]) {
                                    case 28:
                                        ret = "OPF_28"; break;
                                    case 64:
                                        ret = "OPF_64"; break;
                            }
                            break;
                        default:
                            ret = "UNKNOWN";
                    }
                    log("getCodecParamString: " + ret);
                    return ret;
                }

                void updateDiffTextforNodes() {
                    for (int i=0; i<levelTwo.size(); i++) {
                        if (levelTwo.get(i).keyMetadataDiff != null) {
                            Iterator<String> itr = levelTwo.get(i).keyMetadataDiff.iterator();
                            for (int k=0; itr.hasNext(); k++) {
                                levelTwo.get(i).diffText = levelTwo.get(i).diffText.concat(getMetadataString(itr.next().getBytes()));
                                levelTwo.get(i).diffText = levelTwo.get(i).diffText.concat("_");
                            }
                        }
                        if (levelTwo.get(i).keyCodecCfgDiff != null) {
                            Iterator<String> itr = levelTwo.get(i).keyCodecCfgDiff.iterator();
                            for (int k=0; itr.hasNext(); k++) {
                                levelTwo.get(i).diffText = levelTwo.get(i).diffText.concat(getCodecParamString(itr.next().getBytes()));
                                levelTwo.get(i).diffText = levelTwo.get(i).diffText.concat("_");
                            }
                        }
                    }

                    for (int i=0; i<levelThree.size(); i++) {
                        if (levelThree.get(i).keyCodecCfgDiff != null) {
                            Iterator<String> itr = levelThree.get(i).keyCodecCfgDiff.iterator();
                            for (int k=0; itr.hasNext(); k++) {
                                levelThree.get(i).diffText = levelThree.get(i).diffText.concat(getCodecParamString(itr.next().getBytes()));
                                levelThree.get(i).diffText = levelThree.get(i).diffText.concat("_");
                            }
                        }
                    }

                    //Concat and update the Description
                    int startIdx = 0;
                    int children = 0;
                    for (int i=0; i<levelTwo.size(); i++) {
                        startIdx = startIdx+ children;
                        children = children + levelTwo.get(i).numSubGroups;
                        for (int j=startIdx; j<startIdx+levelTwo.get(i).numSubGroups||j<levelThree.size(); j++) {
                            levelThree.get(j).description = levelTwo.get(i).diffText +     levelThree.get(j).diffText;
                        }
                    }
                }

                void updateUniquenessForLevelTwo(int numNodes) {
                    log("updateUniquenessForLevelTwo: ENTER");
                    Set<String> uniqueCodecIds = new LinkedHashSet<String>();
                    Set<String> uniqueCsfs = new LinkedHashSet<String>();
                    Set<String> uniqueMetadatas = new LinkedHashSet<String>();

                    log("updateUniquenessForLevelTwo");

                    int startIdx = 0;
                    int children = 0;
                    for (int i=0; i<levelTwo.size(); i++) {
                        //levelTwo.get(i).print();
                        if (!levelTwo.get(i).isCodecIdUnknown()) {
                            log("add codecId of subg: " + i);
                            String s = new String(levelTwo.get(i).codecId);
                            uniqueCodecIds.add(s);
                        }

                        if (levelTwo.get(i).codecConfigLength != 0) {
                            log("add codecConfig of subg: " + i);
                            String s = new String(levelTwo.get(i).codecConfigInfo);
                            uniqueCsfs.add(s);
                        }

                        if (levelTwo.get(i).metaDataLength != 0) {
                            String s = new String(levelTwo.get(i).metaData);
                            log("add metadata of subg: " + i);
                            uniqueMetadatas.add(s);
                        }
                        startIdx = startIdx+ children;
                        children = children + levelTwo.get(i).numSubGroups;

                        updateUniquenessForLevelThree(i, startIdx, levelTwo.get(i).numSubGroups);
                    }

                    Set<String> uniqueCodecParams = new LinkedHashSet<String>();
                    Set<String> uniqueMetadataParams = new LinkedHashSet<String>();

                    if (uniqueCodecIds.size() > 0) log("LevelTwo: UniqueCodecIds");

                    if (uniqueCsfs.size() > 0) {
                        log("LevelTwo: uniqueCsfs");
                        //uniqueCodecParams =
                        Iterator<String> itr = uniqueCsfs.iterator();
                        for (int i=0; itr.hasNext(); i++) {
                            byte[] ltvEntries = itr.next().getBytes();

                            int k = 0;
                            byte length = ltvEntries[k++];
                            byte[] ltv = new byte[length+1];
                            ltv[0] = length;
                            System.arraycopy(ltvEntries, k, ltv, 1, length);
                            //This should ensure Duplicate entries at this level
                            String s = new String(ltvEntries);
                            uniqueCodecParams.add(s);
                        }
                    }
                    if (uniqueMetadatas.size() > 0) {
                        log("LevelTwo: uniqueMetadatas");
                        //uniqueMetadataParams = new LinkedHashSet<String>();
                        Iterator<String> itr = uniqueMetadatas.iterator();
                        for (int i=0; itr.hasNext(); i++) {
                            byte[] ltvEntries = itr.next().getBytes();

                            int k = 0;
                            byte length = ltvEntries[k++];
                            byte[] ltv = new byte[length+1];
                            ltv[0] = length;
                            System.arraycopy(ltvEntries, k, ltv, 1, length);
                            //This should ensure Duplicate entries at this level
                            String s = new String(ltvEntries);
                            uniqueMetadataParams.add(s);
                        }
                    }

                    //run though the nodes and update KEY differentiating factors
                    if (uniqueCodecParams != null) {
                        Iterator<String> itr = uniqueCodecParams.iterator();
                        int i = 0;
                        for (int k=0; itr.hasNext(); k++) {
                            levelTwo.get(i).keyCodecCfgDiff.add(itr.next());
                            i = (i+1)%(numNodes);
                        }
                    }

                    //run though the nodes and update KEY differentiating factors
                    if (uniqueMetadataParams != null) {
                        Iterator<String> itr = uniqueMetadataParams.iterator();
                        int i = 0;
                        for (int k=0; itr.hasNext(); k++) {
                            levelTwo.get(i).keyMetadataDiff.add(itr.next());
                            i = (i+1)%(numNodes);
                        }
                    }

                    /*log("Level2: Uniqueness among subgroups");
                    if (uniqueCodecParams != null) {
                        Iterator<String> itr = uniqueCodecParams.iterator();
                        for (int k=0; itr.hasNext(); k++) {
                            log("UniqueCodecParams:[" + k + "]" + Arrays.toString(itr.next().getBytes()));
                        }
                    }
                    if (uniqueMetadataParams != null) {
                        Iterator<String>  itr = uniqueMetadataParams.iterator();
                        for (int k=0; itr.hasNext(); k++) {
                            log("uniqueMetadataParams:["+ k + "]" + Arrays.toString(itr.next().getBytes()));
                        }
                    }
                    log("END: Level2: Uniqueness among subgroups");
                    */
                }
                void updateUniquenessForLevelThree(int parentSubgroup, int startIdx, int numNodes) {
                    //Set<String> uniqueCodecIds = new LinkedHashSet<String>();
                    Set<String> uniqueCsfs = new LinkedHashSet<String>();
                    //Set<String> uniqueMetadatas = new LinkedHashSet<String>();

                    log("updateUniquenessForLevelThree: startIdx" + startIdx + "numNodes" + numNodes);
                    for (int i=startIdx; i<startIdx+numNodes||i<levelThree.size(); i++) {
                        if (levelThree.get(i).codecConfigLength != 0) {
                            String s = new String(levelThree.get(i).codecConfigInfo);
                            uniqueCsfs.add(s);
                            log("LEVEL3: add unique CSFs:");
                        }
                    }

                    Set<String> uniqueCodecParams = new LinkedHashSet<String>();
                    if (uniqueCsfs.size() > 0) {
                        log("LevelThree: uniqueCsfs");
                        //uniqueCodecParams =
                        Iterator<String> itr = uniqueCsfs.iterator();
                        for (int i=0; itr.hasNext(); i++) {
                            byte[] ltvEntries = itr.next().getBytes();

                            int k = 0;
                            byte length = ltvEntries[k++];
                            byte[] ltv = new byte[length+1];
                            ltv[0] = length;
                            System.arraycopy(ltvEntries, k, ltv, 1, length);
                            //This should ensure Duplicate entries at this level
                            String s = new String(ltvEntries);
                            uniqueCodecParams.add(s);
                        }
                    }
                    //run though the nodes and update KEY differentiating factors
                    if (uniqueCodecParams != null) {
                        Iterator<String> itr = uniqueCodecParams.iterator();
                        int i = startIdx;
                        for (int k=0; itr.hasNext(); k++) {
                            levelThree.get(i).keyCodecCfgDiff.add(itr.next());
                            i = (i+1)%(startIdx+numNodes);
                        }
                    }
                    /*
                    log("Level3: Uniqueness among children of " + parentSubgroup + "th Subgroup");
                    if (uniqueCodecParams != null) {
                        Iterator<String> itr = uniqueCodecParams.iterator();
                        for (int k=0; itr.hasNext(); k++) {
                            log("UniqueCodecParams:[" + k + "]" + Arrays.toString(itr.next().getBytes()));

                        }
                    }
                    log("END: Level3: Uniqueness among children of " + parentSubgroup + "th Subgroup");
                    */
             }

             void print() {
                levelOne.print();
                log("----- Level TWO BASE ----");
                for (int i=0; i<levelTwo.size(); i++) {
                    levelTwo.get(i).print();
                }
                log("----- Level THREE BASE ----");
                for (int i=0; i<levelThree.size(); i++) {
                    levelThree.get(i).print();
                }
            }

            void printConsolidated() {
                log("----- printConsolidated ----");
                for (int i=0; i<levelThree.size(); i++) {
                    levelThree.get(i).printConsolidated();
                }
            }

            static void log(String msg) {
                if (BassClientStateMachine.BASS_DBG) {
                   Log.d(TAG, msg);
            }
    }
}
