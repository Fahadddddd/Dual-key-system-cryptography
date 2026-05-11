#include <Adafruit_Fingerprint.h>
#include <HardwareSerial.h>

HardwareSerial mySerial(2);

Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);

uint8_t templateBuffer[534];

void setup() {

  Serial.begin(115200);

  mySerial.begin(57600, SERIAL_8N1, 16, 17);

  finger.begin(57600);

  if (finger.verifyPassword()) {
    Serial.println("Sensor found");
  } else {
    Serial.println("Sensor NOT found");
    while (1);
  }
}

void loop() {

  Serial.println("Place finger...");

  while (finger.getImage() != FINGERPRINT_OK);

  Serial.println("Image taken");

  if (finger.image2Tz(1) != FINGERPRINT_OK) {
    Serial.println("Template conversion failed");
    return;
  }

  Serial.println("Uploading template...");

  uint8_t p = finger.getModel();

  if (p != FINGERPRINT_OK) {
    Serial.println("Failed to get template");
    return;
  }

  // Read template data from UART
  while (mySerial.available()) {
    mySerial.read();
  }

  delay(1000);

  Serial.println("BEGIN_TEMPLATE");

  while (mySerial.available()) {

    uint8_t b = mySerial.read();

    if (b < 16)
      Serial.print("0");

    Serial.print(b, HEX);
  }

  Serial.println();

  Serial.println("END_TEMPLATE");

  delay(5000);
}