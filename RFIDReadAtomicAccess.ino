#include <SPI.h>
#include <MFRC522.h>
 
//#define RST_PIN 9 // Configurable, see typical pin layout above
//#define SS_PIN 10 // Configurable, see typical pin layout above
const int RST_PIN = 22; // Reset pin
const int SS_PIN = 21; // Slave select pin

void authenticate(byte trailer);
void dump_MIFARE1K_blocks_to_serial(byte *buffer, byte numOfBlocks);
bool readSingleBlockRecursive(byte * blockBuffer, byte blockAdd, unsigned int recCalls, byte trailer);
void readMIFARE1KBDatablocksSeperately(byte *retVal, uint sizeOfBuffer);
byte getCorrespondingTrailer(byte dataBlock, bool useSerial = true);
 
MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance
MFRC522::MIFARE_Key key = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
MFRC522::StatusCode status;
byte sixteen = 16;

 
void setup() {
	Serial.begin(9600); // Initialize serial communications with the PC
	while (!Serial); // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
	SPI.begin(); // Init SPI bus

}
 
void loop() {
	mfrc522.PCD_Init(); // Init MFRC522
	mfrc522.PCD_DumpVersionToSerial(); // Show details of PCD - MFRC522 Card Reader details
	Serial.println(F("Scan PICC to see UID, SAK, type, and data blocks..."));


	// --- Start new scan on button press
	Serial.println("Drüggsch nen Knop gehts los");

	// --- Read all to make sure no old inputs are in buffer
	while (Serial.peek() != -1)
	{
		Serial.read();
	}
	// --- wait for press
	while (!Serial.available());

	
	// Look for new cards
	if ( ! mfrc522.PICC_IsNewCardPresent()) {
	return;
	}
   
	// Select one of the cards
	if ( ! mfrc522.PICC_ReadCardSerial()) {
	return;
	}
  
	byte blockContents[1024];
	//clean mem
	for (uint i = 0; i < 1024; i++){
		blockContents[i] = 0x11;
	}

	readMIFARE1KBDatablocksSeperately(&blockContents[0], 1024);

	dump_MIFARE1K_blocks_to_serial(&blockContents[0], 64);
}

void authenticate(byte trailer) {
	//neu init
	mfrc522.PICC_HaltA();
	mfrc522.PCD_StopCrypto1();
	mfrc522.PCD_Init();

	//---Look for new cards
	if (!mfrc522.PICC_IsNewCardPresent()) {
		return;
	}

	//---Select one of the cards
	if (!mfrc522.PICC_ReadCardSerial()) {
		return;
	}

	// Authenticate using key B
	Serial.print(F("Authenticating using key A in sector trailer "));
	Serial.println(trailer);
	status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailer, &key, &(mfrc522.uid));
	if (status != MFRC522::STATUS_OK) {
		Serial.print(F("PCD_Authenticate() failed: "));
		Serial.println(mfrc522.GetStatusCodeName(status));
	}
}


//starts at block 1 (first data block) and reads up until it reaches the limit of retVal/the end of the MIFARE 1K
void readMIFARE1KBDatablocksSeperately(byte *retVal, uint sizeOfBuffer) {
	
	/*if (sizeof(retVal) < wantedBlocks * 16){
		Serial.println("Buffer to small for requested blocks");
		mfrc522.PICC_HaltA();
		return;
	}*/

	byte trailerBlock = 255;
	byte readBlockNum = 0;	//to count until retSize
	byte wantedBlocks = sizeOfBuffer / 16;

	//Serial.print("Started reading blocks. Number of wanted blocks: ");
	//Serial.println(wantedBlocks);

	uint currentBlockAddr = 0;
	for (currentBlockAddr = 1; currentBlockAddr < 63; currentBlockAddr++) {
		uint curBlockStartbyte = currentBlockAddr * 16;
		if (readBlockNum > wantedBlocks) {	//nicht mehr einlesen als erwünscht
			return;
		}
		
		trailerBlock = getCorrespondingTrailer(currentBlockAddr, true);		//n�chster trailerBlock

		if (trailerBlock == 255) {
			Serial.print("Continuing because block ");
			Serial.println(currentBlockAddr);
			Serial.println(" is not a data block.");
			continue;
		}

		Serial.print("Reading block ");
		Serial.print(currentBlockAddr);
		Serial.print(" starting at byte ");
		Serial.println(curBlockStartbyte);

		bool blockSuccess = readSingleBlockRecursive(retVal + curBlockStartbyte, currentBlockAddr, 0, trailerBlock);

		readBlockNum++;
		//Serial.print("Blocks read: ");
		//Serial.println(readBlockNum);

		//Serial.print("currentBlockAddr is now ");
		//Serial.println(currentBlockAddr);
	}

	mfrc522.PICC_HaltA();

	Serial.print("Returning because currentBlockAddr is ");
	Serial.println(currentBlockAddr);

}

bool readSingleBlockRecursive(byte * blockBuffer, byte blockAdd, unsigned int recCalls, byte trailer)
{
	if (recCalls > 15) {
		Serial.println();
		Serial.print("Read of block ");
		Serial.print(blockAdd);
		Serial.println(" failed.");
		return false;
	}

	//Serial.println("Saving 16");


	//Serial.println("Saving 16 done");
	byte bufferAndCRC[18];
	byte byteCount = sizeof(bufferAndCRC);

	MFRC522::StatusCode readStatus;
	authenticate(trailer);

	readStatus = mfrc522.MIFARE_Read(blockAdd, bufferAndCRC, &byteCount);

	if (readStatus != MFRC522::STATUS_OK) {
		Serial.print("Reading failed on try ");
		Serial.print(recCalls);
		Serial.print(" for the following reason: ");
		Serial.print(mfrc522.GetStatusCodeName(readStatus));
		Serial.println(" , trying again...");
		return readSingleBlockRecursive(blockBuffer, blockAdd, recCalls + 1, trailer);
	}

	for (uint i = 0; i < 16; i++) {
		*(blockBuffer + i) = bufferAndCRC[i];
	}

	Serial.print("Reading of block ");
	Serial.print(blockAdd);
	Serial.print(" successful after ");
	Serial.print(recCalls + 1);
	if (recCalls == 0)
		Serial.println(" try.");
	else
		Serial.println(" tries.");

	return true;
}

//returns the trailer of the input data block -  returns 255 if block is not a data block
byte getCorrespondingTrailer(byte dataBlock, bool useSerial) {
	if ((dataBlock + 1) % 4 == 0 || dataBlock == 0) {
		if (useSerial) {
			Serial.print("Block ");
			Serial.print(dataBlock);
			Serial.println(" is not a data block.");
		}
		return 255;
	}
	byte trailer = dataBlock + 3 - (dataBlock % 4);
	if (useSerial) {
		Serial.print("Block ");
		Serial.print(dataBlock);
		Serial.print(" has trailer ");
		Serial.println(trailer);
	}

	return trailer;
}


//schreibt jeweils einen Block pro Zeile 
void dump_MIFARE1K_blocks_to_serial(byte *buffer, byte numOfBlocks) {
	for (byte curBlock = 0; curBlock < numOfBlocks; curBlock++) {
		byte isBlockTrailer = getCorrespondingTrailer(curBlock, false);

		uint curStartByte = curBlock * 16;
		if (curBlock < 10) {
			Serial.print("0");
			Serial.print(curBlock);
		}
		else
			Serial.print(curBlock);
		Serial.print("   -   ");

		if (isBlockTrailer == 255) {
			if (curBlock == 0)
				Serial.print("HEADER");
			else
				Serial.print("TRAILER");
		}
		else
			for (byte i = 0; i < 16; i++) {
				Serial.print(buffer[curStartByte + i] < 0x10 ? " 0" : " ");
				Serial.print(buffer[curStartByte + i], HEX);
				Serial.print(" ");
			}
		Serial.println();
	}
}

