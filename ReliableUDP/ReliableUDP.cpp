// ReliableUDP.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
// To run the server start ReliableUDP.exe without arguments. 
// To run the client start ReliableUDP.exe <server ip address>. For example, ReliableUDP.exe 127.0.0.1


/*
	Reliability and Flow Control Example
	From "Networking for Game Programmers" - http://www.gaffer.org/networking-for-game-programmers
	Author: Glenn Fiedler <gaffer@gaffer.org>
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "Net.h"


// ----My Code---- : 
// Application level protocolpacket types. 
// These run on the top of given reliable UDP system.
enum PacketType : uint8_t {
	PACKET_FILE_INFO = 1,  // metadata before file transfer
	PACKET_FILE_DATA = 2,  // actual file chunks
	PACKET_FILE_DONE = 3,  // checksum and completion signal 
};

// ---My Code---
// Pack structs tightly so no padding breaks binary layout.
#pragma pack(push, 1)

// -- My Code--
//FILE_INFO packet: sent once at start of transfer.
// Contains ifle size, chunk size, and filename.
struct FileInfoPacket {
	uint8_t type; // PACKET_FILE_INFO
	uint32_t fileSize;  // total file size in bytes
	uint32_t chunkSize; // size of each chunk
	uint8_t fileNameLen; // lenght of filename (no null terminator)
};  //  followed by filename bytes

// ---My Code---
// FILE_DATA packet: sent many times.
// Contains chunk index and chunk data.
struct FileDataPacket {
	uint8_t type;  // PACKET_FILE_DATA
	uint32_t chunkIndex; // which chunk this is 
	uint32_t chuckSize; // number of bytes in this chunk
	// followed by chunkSize bytes of file data
};

//---MY Code--
// FILE_DONE packet: sent once at end
// Contains final checksum + file size
struct FileDonePacket {
	uint8_t type; // PACKET_FILE_DONE
	uint32_t fileSize; // total file size
	uint8_t checksum[16]; // MD5 checksum - 16 bytes
};

//---MY Code---
#pragma pack(pop)


//#define SHOW_ACKS

using namespace std;
using namespace net;

const int ServerPort = 30000;
const int ClientPort = 30001;
const int ProtocolId = 0x11223344;
const float DeltaTime = 1.0f / 30.0f;
const float SendRate = 1.0f / 30.0f;
const float TimeOut = 10.0f;
const int PacketSize = 256;  //---

class FlowControl
{
public:

	FlowControl()
	{
		printf("flow control initialized\n");
		Reset();
	}

	void Reset()
	{
		mode = Bad;
		penalty_time = 4.0f;
		good_conditions_time = 0.0f;
		penalty_reduction_accumulator = 0.0f;
	}

	void Update(float deltaTime, float rtt)
	{
		const float RTT_Threshold = 250.0f;

		if (mode == Good)
		{
			if (rtt > RTT_Threshold)
			{
				printf("*** dropping to bad mode ***\n");
				mode = Bad;
				if (good_conditions_time < 10.0f && penalty_time < 60.0f)
				{
					penalty_time *= 2.0f;
					if (penalty_time > 60.0f)
						penalty_time = 60.0f;
					printf("penalty time increased to %.1f\n", penalty_time);
				}
				good_conditions_time = 0.0f;
				penalty_reduction_accumulator = 0.0f;
				return;
			}

			good_conditions_time += deltaTime;
			penalty_reduction_accumulator += deltaTime;

			if (penalty_reduction_accumulator > 10.0f && penalty_time > 1.0f)
			{
				penalty_time /= 2.0f;
				if (penalty_time < 1.0f)
					penalty_time = 1.0f;
				printf("penalty time reduced to %.1f\n", penalty_time);
				penalty_reduction_accumulator = 0.0f;
			}
		}

		if (mode == Bad)
		{
			if (rtt <= RTT_Threshold)
				good_conditions_time += deltaTime;
			else
				good_conditions_time = 0.0f;

			if (good_conditions_time > penalty_time)
			{
				printf("*** upgrading to good mode ***\n");
				good_conditions_time = 0.0f;
				penalty_reduction_accumulator = 0.0f;
				mode = Good;
				return;
			}
		}
	}

	float GetSendRate()
	{
		return mode == Good ? 30.0f : 10.0f;
	}

private:

	enum Mode
	{
		Good,
		Bad
	};

	Mode mode;
	float penalty_time;
	float good_conditions_time;
	float penalty_reduction_accumulator;
};

// ============================================================================
// MD5 IMPLEMENTATION (Public Domain - RSA Data Security, Inc. MD5 Algorithm)
// Source Reference: RFC 1321 (https://www.rfc-editor.org/rfc/rfc1321)
// This implementation is simplified and adapted for assignment use.
// ============================================================================

#include <stdint.h>
#include <string.h>

// MD5 context holds state during hashing
struct MD5Context {
	uint32_t state[4];   // A, B, C, D registers
	uint32_t count[2];   // Number of bits processed
	unsigned char buffer[64]; // Input buffer
};

// Forward declaration
void MD5Transform(uint32_t state[4], const unsigned char block[64]);

// Initialize MD5 context
void MD5Init(MD5Context* ctx) {
	ctx->count[0] = ctx->count[1] = 0;

	// Load magic initialization constants
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

// Update MD5 with new data
void MD5Update(MD5Context* ctx, const unsigned char* input, size_t len) {
	size_t index = (ctx->count[0] >> 3) & 0x3F;

	// Update bit count
	ctx->count[0] += (uint32_t)len << 3;
	if (ctx->count[0] < ((uint32_t)len << 3))
		ctx->count[1]++;
	ctx->count[1] += (uint32_t)len >> 29;

	size_t partLen = 64 - index;
	size_t i = 0;

	// Transform as many 64-byte blocks as possible
	if (len >= partLen) {
		memcpy(&ctx->buffer[index], input, partLen);
		MD5Transform(ctx->state, ctx->buffer);

		for (i = partLen; i + 63 < len; i += 64)
			MD5Transform(ctx->state, &input[i]);

		index = 0;
	}

	// Buffer remaining input
	memcpy(&ctx->buffer[index], &input[i], len - i);
}

// Finalize MD5 and produce 16-byte digest
void MD5Final(unsigned char digest[16], MD5Context* ctx) {
	unsigned char bits[8];

	// Save number of bits
	for (int i = 0; i < 4; ++i) {
		bits[i] = (unsigned char)(ctx->count[0] >> (i * 8));
		bits[i + 4] = (unsigned char)(ctx->count[1] >> (i * 8));
	}

	// Pad to 56 bytes
	size_t index = (ctx->count[0] >> 3) & 0x3F;
	size_t padLen = (index < 56) ? (56 - index) : (120 - index);

	static unsigned char PADDING[64] = { 0x80 };
	MD5Update(ctx, PADDING, padLen);

	// Append length
	MD5Update(ctx, bits, 8);

	// Store final state in digest
	for (int i = 0; i < 4; ++i) {
		digest[i] = (unsigned char)(ctx->state[0] >> (i * 8));
		digest[i + 4] = (unsigned char)(ctx->state[1] >> (i * 8));
		digest[i + 8] = (unsigned char)(ctx->state[2] >> (i * 8));
		digest[i + 12] = (unsigned char)(ctx->state[3] >> (i * 8));
	}
}

// MD5 basic functions
#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
#define STEP(f,a,b,c,d,x,t,s) a = b + ROTATE_LEFT(a + f(b,c,d) + x + t, s)

// Transform a 64-byte block
void MD5Transform(uint32_t state[4], const unsigned char block[64]) {
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	// Decode block into 16 uint32s
	for (int i = 0; i < 16; ++i)
		x[i] = (uint32_t)block[i * 4] |
		((uint32_t)block[i * 4 + 1] << 8) |
		((uint32_t)block[i * 4 + 2] << 16) |
		((uint32_t)block[i * 4 + 3] << 24);

	// Round 1
	STEP(F, a, b, c, d, x[0], 0xd76aa478, 7);
	STEP(F, d, a, b, c, x[1], 0xe8c7b756, 12);
	STEP(F, c, d, a, b, x[2], 0x242070db, 17);
	STEP(F, b, c, d, a, x[3], 0xc1bdceee, 22);
	STEP(F, a, b, c, d, x[4], 0xf57c0faf, 7);
	STEP(F, d, a, b, c, x[5], 0x4787c62a, 12);
	STEP(F, c, d, a, b, x[6], 0xa8304613, 17);
	STEP(F, b, c, d, a, x[7], 0xfd469501, 22);
	STEP(F, a, b, c, d, x[8], 0x698098d8, 7);
	STEP(F, d, a, b, c, x[9], 0x8b44f7af, 12);
	STEP(F, c, d, a, b, x[10], 0xffff5bb1, 17);
	STEP(F, b, c, d, a, x[11], 0x895cd7be, 22);
	STEP(F, a, b, c, d, x[12], 0x6b901122, 7);
	STEP(F, d, a, b, c, x[13], 0xfd987193, 12);
	STEP(F, c, d, a, b, x[14], 0xa679438e, 17);
	STEP(F, b, c, d, a, x[15], 0x49b40821, 22);

	// Round 2
	STEP(G, a, b, c, d, x[1], 0xf61e2562, 5);
	STEP(G, d, a, b, c, x[6], 0xc040b340, 9);
	STEP(G, c, d, a, b, x[11], 0x265e5a51, 14);
	STEP(G, b, c, d, a, x[0], 0xe9b6c7aa, 20);
	STEP(G, a, b, c, d, x[5], 0xd62f105d, 5);
	STEP(G, d, a, b, c, x[10], 0x02441453, 9);
	STEP(G, c, d, a, b, x[15], 0xd8a1e681, 14);
	STEP(G, b, c, d, a, x[4], 0xe7d3fbc8, 20);
	STEP(G, a, b, c, d, x[9], 0x21e1cde6, 5);
	STEP(G, d, a, b, c, x[14], 0xc33707d6, 9);
	STEP(G, c, d, a, b, x[3], 0xf4d50d87, 14);
	STEP(G, b, c, d, a, x[8], 0x455a14ed, 20);
	STEP(G, a, b, c, d, x[13], 0xa9e3e905, 5);
	STEP(G, d, a, b, c, x[2], 0xfcefa3f8, 9);
	STEP(G, c, d, a, b, x[7], 0x676f02d9, 14);
	STEP(G, b, c, d, a, x[12], 0x8d2a4c8a, 20);

	// Round 3
	STEP(H, a, b, c, d, x[5], 0xfffa3942, 4);
	STEP(H, d, a, b, c, x[8], 0x8771f681, 11);
	STEP(H, c, d, a, b, x[11], 0x6d9d6122, 16);
	STEP(H, b, c, d, a, x[14], 0xfde5380c, 23);
	STEP(H, a, b, c, d, x[1], 0xa4beea44, 4);
	STEP(H, d, a, b, c, x[4], 0x4bdecfa9, 11);
	STEP(H, c, d, a, b, x[7], 0xf6bb4b60, 16);
	STEP(H, b, c, d, a, x[10], 0xbebfbc70, 23);
	STEP(H, a, b, c, d, x[13], 0x289b7ec6, 4);
	STEP(H, d, a, b, c, x[0], 0xeaa127fa, 11);
	STEP(H, c, d, a, b, x[3], 0xd4ef3085, 16);
	STEP(H, b, c, d, a, x[6], 0x04881d05, 23);
	STEP(H, a, b, c, d, x[9], 0xd9d4d039, 4);
	STEP(H, d, a, b, c, x[12], 0xe6db99e5, 11);
	STEP(H, c, d, a, b, x[15], 0x1fa27cf8, 16);
	STEP(H, b, c, d, a, x[2], 0xc4ac5665, 23);

	// Round 4
	STEP(I, a, b, c, d, x[0], 0xf4292244, 6);
	STEP(I, d, a, b, c, x[7], 0x432aff97, 10);
	STEP(I, c, d, a, b, x[14], 0xab9423a7, 15);
	STEP(I, b, c, d, a, x[5], 0xfc93a039, 21);
	STEP(I, a, b, c, d, x[12], 0x655b59c3, 6);
	STEP(I, d, a, b, c, x[3], 0x8f0ccc92, 10);
	STEP(I, c, d, a, b, x[10], 0xffeff47d, 15);
	STEP(I, b, c, d, a, x[1], 0x85845dd1, 21);
	STEP(I, a, b, c, d, x[8], 0x6fa87e4f, 6);
	STEP(I, d, a, b, c, x[15], 0xfe2ce6e0, 10);
	STEP(I, c, d, a, b, x[6], 0xa3014314, 15);
	STEP(I, b, c, d, a, x[13], 0x4e0811a1, 21);
	STEP(I, a, b, c, d, x[4], 0xf7537e82, 6);
	STEP(I, d, a, b, c, x[11], 0xbd3af235, 10);
	STEP(I, c, d, a, b, x[2], 0x2ad7d2bb, 15);
	STEP(I, b, c, d, a, x[9], 0xeb86d391, 21);

	// Add this block's hash to result
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

// Convenience wrapper
void ComputeMD5(const unsigned char* data, size_t len, unsigned char out[16]) {
	MD5Context ctx;
	MD5Init(&ctx);
	MD5Update(&ctx, data, len);
	MD5Final(out, &ctx);
}



// ----------------------------------------------

int main(int argc, char* argv[])
{
	// parse command line

	enum Mode
	{
		Client,
		Server
	};

	// change the port depending on whether we are a client or server
	Mode mode = Server;
	Address address;

    #pragma warning(suppress : 4996)

	if (argc >= 2)
	{
		int a, b, c, d;
		if (sscanf_s(argv[1], "%d.%d.%d.%d", &a, &b, &c, &d))
		{
			mode = Client;
			address = Address(a, b, c, d, ServerPort);
		}
	}
	// ------------------------------------------------------------
    // Ask user which file to send
	// Nathanael;s code
	// ------------------------------------------------------------
	std::string filePath;
	uint32_t fileSize = 0;
	std::vector<unsigned char> fileData;

	if (mode == Client)
	{
		std::cout << "Enter file path to send: ";
		std::getline(std::cin, filePath);

		// Open file in binary mode. This supports ANY file type
		std::ifstream in(filePath, std::ios::binary);

		if (!in)
		{
			std::cout << "Failed to open file\n";
			return 1;
		}

		// Determine file size
		in.seekg(0, std::ios::end);
		fileSize = (uint32_t)in.tellg();
		in.seekg(0, std::ios::beg);

		// Read entire file into memory buffer
		fileData.resize(fileSize);
		in.read((char*)fileData.data(), fileSize);

		// The Compute MD5 function has not been implemented yet, I will comment it out, Nathanael
		//uint8_t checksum[16];
		//ComputeMD5(fileData.data(), fileSize, checksum);
	}

	// initialize

	if (!InitializeSockets())
	{
		printf("failed to initialize sockets\n");
		return 1;
	}

	ReliableConnection connection(ProtocolId, TimeOut);
	
	const int port = mode == Server ? ServerPort : ClientPort;

	if (!connection.Start(port))
	{
		printf("could not start connection on port %d\n", port);
		return 1;
	}

	if (mode == Client)
		connection.Connect(address);
	else
		connection.Listen();

	// ------------------------------------------------------------
	// Choose chunk size. Must fit inside Reliable UDP packet
	// Nathanael's 
	// ------------------------------------------------------------

	uint32_t chunkSize = 1024;

	//Extract filename from path
	std::string fileName = filePath.substr(filePath.find_last_of("/\\") + 1);

	//Build FILE_INFO packet
	FileInfoPacket info{};
	info.type = PACKET_FILE_INFO;
	info.fileSize = fileSize;
	info.chunkSize = chunkSize;
	info.fileNameLen = (uint8_t)fileName.size();

	//Allocate buffer: struct + filename bytes
	std::vector<unsigned char> packet(sizeof(FileInfoPacket) + fileName.size());
	// Copy struct + filename into packet
    memcpy(packet.data(), &info, sizeof(FileInfoPacket));
	memcpy(packet.data() + sizeof(FileInfoPacket), fileName.data(), fileName.size());

	// Send through reliable UDP
	connection.SendPacket(packet.data(), packet.size());

	// ------------------------------------------------------------
    // Break file into chunks and send each one
	// Nathanael's
    // --------------------------------------------------------------
	uint32_t numChunks = (fileSize + chunkSize - 1) / chunkSize;

	for (uint32_t i = 0; i < numChunks; ++i)
	{
		uint32_t offset = i * chunkSize;
		uint32_t thisSize = (std::min)(chunkSize, fileSize - offset);

		// Build header
		FileDataPacket header{};
		header.type = PACKET_FILE_DATA;
		header.chunkIndex = i;
		header.chuckSize = thisSize;

		// Allocate packet buffer
		std::vector<unsigned char> packet(
			sizeof(FileDataPacket) + thisSize);

		// Copy header + chunk data
		memcpy(packet.data(),
			&header,
			sizeof(FileDataPacket));

		memcpy(packet.data() + sizeof(FileDataPacket),
			fileData.data() + offset,
			thisSize);

		// Send chunk
		connection.SendPacket(packet.data(), packet.size());
	}


	bool connected = false;
	float sendAccumulator = 0.0f;
	float statsAccumulator = 0.0f;

	FlowControl flowControl;

	while (true)
	{
		// update flow control

		if (connection.IsConnected())
			flowControl.Update(DeltaTime, connection.GetReliabilitySystem().GetRoundTripTime() * 1000.0f);

		const float sendRate = flowControl.GetSendRate();

		// detect changes in connection state

		if (mode == Server && connected && !connection.IsConnected())
		{
			flowControl.Reset();
			printf("reset flow control\n");
			connected = false;
		}

		if (!connected && connection.IsConnected())
		{
			printf("client connected to server\n");
			connected = true;
		}

		if (!connected && connection.ConnectFailed())
		{
			printf("connection failed\n");
			break;
		}

		// send and receive packets

		sendAccumulator += DeltaTime;

		while (sendAccumulator > 1.0f / sendRate)
		{
			unsigned char packet[PacketSize];
			memset(packet, 0, sizeof(packet));
			connection.SendPacket(packet, sizeof(packet));
			sendAccumulator -= 1.0f / sendRate;
		}

		while (true)
		{
			unsigned char packet[PacketSizeHack];
			int bytes_read = connection.ReceivePacket(packet, sizeof(packet));
			if (bytes_read == 0)
				break;
		}

		// show packets that were acked this frame

#ifdef SHOW_ACKS
		unsigned int* acks = NULL;
		int ack_count = 0;
		connection.GetReliabilitySystem().GetAcks(&acks, ack_count);
		if (ack_count > 0)
		{
			printf("acks: %d", acks[0]);
			for (int i = 1; i < ack_count; ++i)
				printf(",%d", acks[i]);
			printf("\n");
		}
#endif

		// update connection

		connection.Update(DeltaTime);

		// show connection stats

		statsAccumulator += DeltaTime;

		while (statsAccumulator >= 0.25f && connection.IsConnected())
		{
			float rtt = connection.GetReliabilitySystem().GetRoundTripTime();

			unsigned int sent_packets = connection.GetReliabilitySystem().GetSentPackets();
			unsigned int acked_packets = connection.GetReliabilitySystem().GetAckedPackets();
			unsigned int lost_packets = connection.GetReliabilitySystem().GetLostPackets();

			float sent_bandwidth = connection.GetReliabilitySystem().GetSentBandwidth();
			float acked_bandwidth = connection.GetReliabilitySystem().GetAckedBandwidth();

			printf("rtt %.1fms, sent %d, acked %d, lost %d (%.1f%%), sent bandwidth = %.1fkbps, acked bandwidth = %.1fkbps\n",
				rtt * 1000.0f, sent_packets, acked_packets, lost_packets,
				sent_packets > 0.0f ? (float)lost_packets / (float)sent_packets * 100.0f : 0.0f,
				sent_bandwidth, acked_bandwidth);

			statsAccumulator -= 0.25f;
		}

		net::wait(DeltaTime);
	}

	ShutdownSockets();

	return 0;
}
