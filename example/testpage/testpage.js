// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: BSD 3-Clause "New" or "Revised" License

/* eslint-disable no-undef */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-shadow */
import { createSFrameClient } from '../../lib/example/Client.js';

const WITH_ENCRYPTION = true;

/*
	 Get some key material to use as input to the deriveKey method.
	 The key material is a secret key supplied by the user.
	 */
async function getRoomKey(roomId, secret) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(secret),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
    );
    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: enc.encode(roomId),
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-CTR', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

async function createParticipant(name, id) {
    const constraints = {
        audio: false, // it works with audio but it is annoying to hear yourself
        video: true,
    };
    const stream = await navigator.mediaDevices.getUserMedia(constraints);
    const stream_settings = stream.getVideoTracks()[0].getSettings();
    const videoSettings = document.getElementById(`${name}_video_settings`);
    videoSettings.innerHTML = `
        width: ${stream_settings.width}<br>
        height: ${stream_settings.height}<br>
        framerate: ${stream_settings.frameRate}<br>
        device label: ${stream.label}
    `;

    const clientConfig = {
        senderId: id,
        mediaType: 'video',
        signalError: (err) => {
            console.log('sender: ', err);
        },
        signalFatalError: (err) => {
            console.log('sender: ', err);
        },
        signalDecryptionStatus: (status) => {
            console.log(
                `DecryptionStatus: pipe: ${status.id} key: ${status.keyId} status: ${status.state}`
            );
        },
    };

    const client = await createSFrameClient(clientConfig);
    const videoTag = document.getElementById(`${name}_local`);

    //Set it on the local video
    videoTag.srcObject = stream;
    videoTag.play();

    return {
        name: name,
        id: id,
        client: client,
        stream: stream,
        inbound: new Map(),
        outbound: new Map(),
    };
}

async function connect(sender, receiver) {
    disconnect(sender, receiver);

    //Get keys
    const senderKey = await getRoomKey(
        'roomId',
        document.getElementById(`${sender.name}Password`).value
    );
    const receiverKey = await getRoomKey(
        'roomId',
        document.getElementById(`${receiver.name}Password`).value
    );

    const senderConnection = new RTCPeerConnection({
        encodedInsertableStreams: true,
    });
    const receiverConnection = new RTCPeerConnection({
        encodedInsertableStreams: true,
    });

    receiverConnection.ontrack = (event) => {
        const stream = event.streams[0];
        const videoTag = document.getElementById(`${receiver.name}_${sender.name}`);
        if (!videoTag.srcObject) {
            //Set src stream
            videoTag.srcObject = stream;
            videoTag.play();
        }
        if (WITH_ENCRYPTION) {
            receiver.client.decrypt(event.receiver, 'video');
        }
    };

    //Interchange candidates
    senderConnection.onicecandidate = ({ candidate: senderCandidate }) =>
        senderCandidate && receiverConnection.addIceCandidate(senderCandidate);
    receiverConnection.onicecandidate = ({ candidate: receiverCandidate }) =>
        receiverCandidate && senderConnection.addIceCandidate(receiverCandidate);

    // Add all tracks
    // Add track
    for (const track of sender.stream.getTracks()) senderConnection.addTrack(track, sender.stream);
    const offer = await senderConnection.createOffer();
    await senderConnection.setLocalDescription(offer);
    await receiverConnection.setRemoteDescription(offer);
    if (WITH_ENCRYPTION) {
        for (const transceiver of senderConnection.getTransceivers()) {
            sender.client.encrypt(transceiver.sender, 'video');
        }
    }
    const answer = await receiverConnection.createAnswer();
    await receiverConnection.setLocalDescription(answer);
    await senderConnection.setRemoteDescription(answer);
    sender.outbound[receiver.id] = senderConnection;
    receiver.inbound[sender.id] = receiverConnection;
}

async function disconnect(sender, receiver) {
    if (!sender || !receiver) {
        return;
    }

    if (sender.outbound[receiver.id]) {
        sender.outbound[receiver.id].close();
    }
    if (receiver.inbound[sender.id]) {
        receiver.inbound[sender.id].close();
        receiver.client.deleteReceiver(sender.id);
    }

    const receiverVideoTag = document.getElementById(`${receiver.name}_${sender.name}`);
    if (receiverVideoTag) {
        receiverVideoTag.srcObject = undefined;
    }
}

async function setSenderPassphrase(sender) {
    const senderKey = await getRoomKey(
        'roomId',
        document.getElementById(`${sender.name}Password`).value
    );
    await sender.client.setSenderEncryptionKey(sender.id, senderKey);
}

async function setReceiverPassphrase(receiver, sender) {
    const receiverKey = await getRoomKey(
        'roomId',
        document.getElementById(`${receiver.name}Password`).value
    );
    await receiver.client.setReceiverEncryptionKey(sender.id, receiverKey);
}

async function updatePassphrases(sender, receiver) {
    await setSenderPassphrase(sender);
    await setReceiverPassphrase(receiver, sender);
}

let alice;
let bob;
let carol;

async function doAction(action) {
    const clients = [alice, bob, carol];
    clients.forEach(function (clientA) {
        clients.forEach(function (clientB) {
            if (clientA === clientB) {
                return;
            }
            action(clientA, clientB);
        });
    });
}

document.getElementById('initButton').onclick = async () => {
    alice = await createParticipant('alice', 0);
    bob = await createParticipant('bob', 1);
    carol = await createParticipant('carol', 2);
};

document.getElementById('connectButton').onclick = () => {
    doAction(connect);
};

document.getElementById('disconnectButton').onclick = () => {
    doAction(disconnect);
};

document.getElementById('updateButton').onclick = () => {
    doAction(updatePassphrases);
};

document.getElementById('alice_send_pw').onclick = () => {
    setSenderPassphrase(alice);
};

document.getElementById('alice_bob_recv_pw').onclick = () => {
    setReceiverPassphrase(alice, bob);
};

document.getElementById('alice_carol_recv_pw').onclick = () => {
    setReceiverPassphrase(alice, carol);
};

document.getElementById('bob_send_pw').onclick = () => {
    setSenderPassphrase(bob);
};

document.getElementById('bob_alice_recv_pw').onclick = () => {
    setReceiverPassphrase(bob, alice);
};

document.getElementById('bob_carol_recv_pw').onclick = () => {
    setReceiverPassphrase(bob, carol);
};


document.getElementById('carol_send_pw').onclick = () => {
    setSenderPassphrase(carol);
};

document.getElementById('carol_bob_recv_pw').onclick = () => {
    setReceiverPassphrase(carol, bob);
};

document.getElementById('carol_alice_recv_pw').onclick = () => {
    setReceiverPassphrase(carol, alice);
};
