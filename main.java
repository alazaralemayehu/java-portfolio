package com.example.auth.ticket;

import android.os.Build;
import android.support.annotation.RequiresApi;

import com.example.auth.app.ulctools.Commands;
import com.example.auth.app.ulctools.Reader;
import com.example.auth.app.ulctools.Utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Ticket {
  private static byte[] defaultAuthenticationKey = "BREAKMEIFYOUCAN!".getBytes(); // 16-byte key
  private static byte[] authenticationKey; // 16-byte key
  private static byte[] hmacKey = "0123456789ABCDEF".getBytes(); // min 16-byte key

  private final String tag = "axal";
  private final int appVersion = 1;

  private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
  private static Utilities utils;
  private static Commands ul;
  private static String infoToShow; // Use this to show messages

  private int remainingUses;
  private int expiryTime;

  private Boolean isValid = false;
  private int counter = -1;

  // Defining Pages for different purposes
  private static final int COUNTER_PAGE = 41;
  private static final int RIDE_PAGE = 6;
  private static final int EXPIRY_TIME_PAGE = 7;
  private static final int TAG_PAGE = 8;
  private static final int APP_VERSION_PAGE = 9;
  private static final int MAC_PAGE = 10;
  private static final int BACKUP_MAC_PAGE = 11;
  private static final int COUNTER_VALUE_PAGE = 15;

  private static final int MAXIMUM_ALLOWED_RIDE = 10;
  private static final int MAXIMUM_ALLOWED_MINUTE = 10;
  private static final int CARD_VALIDITY_TIME_MIN = 2;

  public static byte[] data = new byte[192];

  /** Create a new ticket */
  public Ticket() throws GeneralSecurityException {
    // Set HMAC key for the ticket
    macAlgorithm = new TicketMac();
    macAlgorithm.setKey(hmacKey);
    ul = new Commands();
    utils = new Utilities(ul);
  }

  private byte[] getAuthenticationKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    if (authenticationKey == null) {
      authenticationKey = calculateKey();
    }
    return authenticationKey;
  }

  /** After validation, get ticket status: was it valid or not? */
  public boolean isValid() {
    return isValid;
  }

  /** After validation, get the number of remaining uses */
  public int getRemainingUses() {
    return remainingUses;
  }

  /** After validation, get the expiry time */
  public int getExpiryTime() {
    return expiryTime;
  }

  private void setInfoToShow(String info) {
    infoToShow = info;
  }

  private void setCustomerInfoToShow(String info) {
    setInfoToShow(info + " Please contact customer service.");
  }

  /** After validation/issuing, get information */
  public static String getInfoToShow() {
    String tmp = infoToShow;
    infoToShow = "";
    return tmp;
  }

  // https://stackoverflow.com/questions/6374915/java-convert-int-to-byte-array-of-4-bytes
  private byte[] convertIntToByte(int number) {
    byte[] byteArray = ByteBuffer.allocate(4).putInt(number).array();
    return byteArray;
  }

  private int convertByteToInt(byte[] byteArray) {
    int number = ByteBuffer.wrap(byteArray).getInt();
    return number;
  }

  /**
   * Returns a uuid of a scanned nfc card It receive no argument
   *
   * @param null
   * @return uuid of NFC card
   */
  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private String getUUID() {
    byte[] uuid = Reader.nfcA_card.getTag().getId();
    StringBuilder stringBuilder = new StringBuilder();

    for (int i = 0; i < uuid.length; i++) {
      byte excludedCharacter = (byte) ':';
      if (uuid[i] == excludedCharacter) {
        continue;
      }
      stringBuilder.append(String.format("%02X:", uuid[i]));
    }
    String uuid_string = String.join("", stringBuilder.toString().split(":"));
    Utilities.log("UUID: " + uuid_string, false);

    return uuid_string;
  }

  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private byte[] calculateMAC() {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    boolean res = readExpiryTime();
    if (!res) {
      Utilities.log("Unable to read expiry time", true);
      return new byte[0];
    }

    res = readRemainingUses();
    if (!res) {
      Utilities.log("Unable to read expiry time", true);
      return new byte[0];
    }

    try {
      byte[] remainingRideByte = convertIntToByte(getRemainingUses());
      byte[] expiryTimeByte = convertIntToByte(getExpiryTime());
      macAlgorithm.setKey((getAuthenticationKey()));

      outputStream.write(getAppTag());
      outputStream.write(getAppVersion());
      outputStream.write(remainingRideByte);
      outputStream.write(expiryTimeByte);
    } catch (Exception ex) {
      Utilities.log("Mac calculation failed: " + ex.fillInStackTrace(), false);
    }

    byte[] generatedMAC = macAlgorithm.generateMac(outputStream.toByteArray());
    return Arrays.copyOfRange(generatedMAC, 0, 4);
  }

  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private boolean writeMAC(int mac_page) {
    byte[] MAC = calculateMAC(); // Arrays.copyOfRange(calculateMAC(),0,4);
    Utilities.log("MAC to write is: " + MAC.toString() + " (length: " + MAC.length + ")", false);
    boolean res = utils.writePages(MAC, 0, mac_page, 1);
    return res;
  }

  private byte[] readMAC(int mac_page) {
    byte[] MAC = new byte[4];
    boolean res = utils.readPages(MAC_PAGE, 1, MAC, 0);
    Utilities.log("Read MAC is: " + new String(MAC), false);
    if (!res) {
      Utilities.log("Unable to read MAC", true);
      return new byte[0];
    }
    return MAC;
  }

  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private boolean isMACCorrect() {
    byte[] readMAC = readMAC(MAC_PAGE);
    byte[] calculatedMAC = calculateMAC();
    return Arrays.equals(readMAC, calculatedMAC);
  }

  /**
   * https://stackoverflow.com/questions/2860943/how-can-i-hash-a-password-in-java/2861125#2861125
   * Calculate the key
   *
   * @return byte array the value of the key
   */
  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private byte[] calculateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    String secretKeyAlgorithmType = "PBKDF2WithHmacSHA1"; // supported since API level 10
    int keyLength = 128; // 128 bits means 4 page
    String salt = "saltpassword";

    KeySpec keySpec = new PBEKeySpec(getUUID().toCharArray(), salt.getBytes(), 100, keyLength);
    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithmType);
    byte[] key = secretKeyFactory.generateSecret(keySpec).getEncoded();
    Utilities.log("Key is: " + new String(key) + " (length: " + key.length + ")", false);
    return key;
  }

  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private boolean changeAuthenticationKey() {
    try {
      byte[] key = authenticationKey;
      return writeToAuthenticationKeyPage(key);
    } catch (Exception ex) {
      return false;
    }
  }

  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private boolean resetAuthenticationKey() {
    authenticationKey = defaultAuthenticationKey;
    try {
      return writeToAuthenticationKeyPage(authenticationKey);
    } catch (Exception ex) {
      return false;
    }
  }

  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private boolean writeToAuthenticationKeyPage(byte[] key) {
    try {
      boolean res = utils.writePages(key, 0, 44, 4);
      return res;
    } catch (Exception exception) {
      Utilities.log("Writing auth key failed: " + exception.fillInStackTrace(), false);
    }
    return true;
  }

  private boolean writeAppVersion() {
    boolean res = utils.writePages(convertIntToByte(appVersion), 0, APP_VERSION_PAGE, 1);
    if (res) {
      Utilities.log("Wrote version: " + appVersion, false);
    }
    return res;
  }

  private int getAppVersion() {
    byte[] appVersionDestination = new byte[4];
    boolean res = utils.readPages(APP_VERSION_PAGE, 1, appVersionDestination, 0);
    return convertByteToInt(appVersionDestination);
  }

  private boolean writeAppTag() {
    boolean res = utils.writePages(tag.getBytes(), 0, TAG_PAGE, 1);
    if (res) {
      Utilities.log("Wrote tag: " + tag, false);
    }
    return res;
  }

  private byte[] getAppTag() {
    byte[] tagDestination = new byte[4];
    boolean res = utils.readPages(TAG_PAGE, 1, tagDestination, 0);
    return tagDestination;
  }

  private boolean writeExpiryTime() {
    expiryTime = calculateExpiryTime();
    return writeTimeStamp(expiryTime);
  }

  /**
   * Returns a boolean indicating weather a expiry time is written in timeStamp page
   *
   * @param timeStamp a timeStamp
   * @return boolean indicating weather exipry time is written or not
   */
  private boolean writeTimeStamp(int timeStamp) {
    Utilities.log("Time written: " + timeStamp, false);
    byte[] expiryDateByte = convertIntToByte(timeStamp);
    return utils.writePages(expiryDateByte, 0, EXPIRY_TIME_PAGE, 1);
  }

  private int calculateCurrentTime() {
    int unixTimestampMin = (int) (new Date().getTime() / 1000 / 60);
    return unixTimestampMin;

  }

  private int calculateExpiryTime() {
    int unixTimestampMin = calculateCurrentTime();
    int expiryTime = unixTimestampMin + CARD_VALIDITY_TIME_MIN;
    return expiryTime;
  }

  private boolean readExpiryTime() {
    byte[] expiryTimeByte = new byte[4];
    boolean res = utils.readPages(EXPIRY_TIME_PAGE, 1, expiryTimeByte, 0);
    int expiryTimeInteger = convertByteToInt(expiryTimeByte);
    expiryTime = expiryTimeInteger;
    return res;
  }

  private boolean isExpired() {
    long currentTime = (new Date().getTime());
    int currentTimeInMinutes = (int) (currentTime / 1000 / 60);
    Utilities.log("Expiration time: " + expiryTime + "  - Current time: " + currentTimeInMinutes, false);
    if (currentTimeInMinutes >= expiryTime) {
      return true;
    }
    return false;
  }

  private boolean hasExpiryTimeExceeded() {
    long currentTime = (new Date().getTime());
    int currentTimeInMinutes = (int) (currentTime / 1000 / 60);
    Utilities.log(
        "Current time: "
            + currentTimeInMinutes
            + " - Maximum allowed: "
            + MAXIMUM_ALLOWED_MINUTE
            + " - Expiry time: "
            + expiryTime, false);

    if (currentTimeInMinutes + MAXIMUM_ALLOWED_MINUTE < expiryTime) {
      return true;
    }
    return false;
  }

  private String convertIntToDate(int timestamp) {
    Date date = new Date(timestamp * 1000L * 60L);
    SimpleDateFormat formatter = new SimpleDateFormat("HH:mm");

    return formatter.format(date);
  }

  private boolean updateRemainingUses(int ride) {
    byte[] rideInByte = convertIntToByte(ride);
    return utils.writePages(rideInByte, 0, RIDE_PAGE, 1);
  }

  private boolean writeRemainingUses() {
    int counterValue = getCounterValue();
    remainingUses = counterValue + 5;
    Utilities.log("Remaining rides: " + remainingUses, false);
    return updateRemainingUses(remainingUses);
  }

  private boolean readRemainingUses() {
    byte[] remainingRideByte = new byte[4];
    boolean res = utils.readPages(RIDE_PAGE, 1, remainingRideByte, 0);
    if (res) {
      remainingUses = convertByteToInt(remainingRideByte);
      return true;
    }
    return false;
  }

  private boolean writeCounterValue() {
    byte counter[] = convertIntToByte(getCounterValue());
    boolean res = utils.writePages(counter, 0, COUNTER_VALUE_PAGE, 1);
    return res;
  }

  private int getCounterFromPage() {
    byte[] counterValue = new byte[4];
    boolean res = utils.readPages(COUNTER_VALUE_PAGE, 1, counterValue, 0);
    if (res) {
      return convertByteToInt(counterValue);
    }
    return -1;
  }

  /**
   * Returns a boolean indicating if all rides are used or not
   *
   * @param null
   * @return int indication of weather there is remaining rides in the card or not
   */
  private boolean areAllRidesUsed() {
    if (getRemainingUses() <= getCounterValue()) {
      Utilities.log("No remaining rides", true);
      return true;
    }
    return false;
  }

  private boolean hasExceededRemainingUses() {
    if (getRemainingUses() > getCounterValue() + MAXIMUM_ALLOWED_RIDE) {
      Utilities.log("Remaining use is more than allowable ride", true);
      return true;
    }
    return false;
  }

  private int getCounterValue() {
    if (counter < 0) {
      return readCounterValue();
    }
    return counter;
  }

  /**
   * Returns a value of counter page
   *
   * @param null
   * @return int Value in counter page
   */
  private int readCounterValue() {
    byte[] counterValue = new byte[4];
    boolean res = utils.readPages(COUNTER_PAGE, 1, counterValue, 0);
    if (!res) {
      return -1;
    }

    int length = counterValue.length;
    for (int i = 0; i < length / 2; i++) {
      byte temp = counterValue[i];
      counterValue[i] = counterValue[length - i - 1];
      counterValue[length - i - 1] = temp;
    }

    counter = convertByteToInt(counterValue);
    Utilities.log("Counter value: " + counter, false);
    return counter;
  }

  /**
   * Increase the counter from the card
   *
   * @param null
   * @return boolean an indicator weather increasing counter was succesfull or not
   */
  private boolean increaseCounter() {
    byte nullByte = (byte) 0x00;
    byte[] countedData = new byte[] {(byte) 0x01, nullByte, nullByte, nullByte};
    boolean res = utils.writePages(countedData, 0, COUNTER_PAGE, 1);
    if (res) {
      counter = readCounterValue();
    }
    return res;
  }

  // https://stackoverflow.com/questions/25206289/how-to-convert-value-back-from-02x-in-java
  // https://gist.github.com/avisagie/1af2f24e1aa1d5beb9b0

  // https://stackoverflow.com/questions/30407340/creating-hex-byte-array-in-java
  private boolean enableProtection() {
    byte[] auth_data = new byte[] {(byte) 5, (byte) 0, (byte) 0, (byte) 0};
    boolean res = utils.writePages(auth_data, 0, 42, 1);
    if (!res) {
      return res;
    }

    auth_data = new byte[] {(byte) 0, (byte) 0, (byte) 0, (byte) 0};
    res = utils.writePages(auth_data, 0, 43, 1);
    return res;
  }

  /**
   * Issue new tickets Check if we can authenticate using the default key, if we are able to, then
   * it means it is first time use treat the card as first time use
   */
  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  public boolean issue(int daysValid, int uses) throws GeneralSecurityException, IOException {
    authenticationKey = getAuthenticationKey();
    remainingUses = uses;
    if (utils.authenticate(defaultAuthenticationKey)) {
      // This is new Card
      // Change the password
      // write the app tag, app version, remaining ride and start time
      Utilities.log("This is new card changing the authentication key", false);
      authenticationKey = calculateKey();
      changeAuthenticationKey();

      if (!writeAppTag()) {
        Utilities.log("Something went wrong while writing app tag!", true);
        isValid = false;
        return false;
      }

      if (!writeAppVersion()) {
        Utilities.log("Something went wrong while writing app version!", true);
        isValid = false;
        return false;
      }

      if (!writeRemainingUses()) {
        isValid = false;
        Utilities.log("Something went wrong while writing remaining usage!", true);
        return false;
      }

      if (!writeExpiryTime()) {
        isValid = false;
        Utilities.log("Unable to Write Expiry time", true);
        return false;
      }

      if (!writeMAC(MAC_PAGE)) {
        isValid = false;
        Utilities.log("Unable to write MAC", true);
        return false;
      }

      // As a backup to protect from tearing attack
      if (!writeMAC(BACKUP_MAC_PAGE)) {
        Utilities.log("Unable to Write Backup MAC", true);
        isValid = false;
        return false;
      }

      if (!writeCounterValue()) {
        Utilities.log("Unable to Write Counter", true);
        isValid = false;
        return false;
      }
    } else {
      if (!utils.authenticate(authenticationKey)) {
        Utilities.log("Unable to Authenticate", false);
        isValid = false;
        return false;
      }

      if (isDataIncorrect()) {
        if (!resetCard()) {
          Utilities.log("Unable to reset in fishy ride", true);
        }
        issue(daysValid, uses);
        return false;
      }

      if (!readRemainingUses()) {
        Utilities.log("Unable to read Remaining Ride", false);
        isValid = false;
        return false;
      }

      if (remainingUses <= getCounterValue()) {
        remainingUses = getCounterValue() + 5;
      } else {
        remainingUses += 5;
      }

      if (!updateRemainingUses(remainingUses)) {
        Utilities.log("Unable to Write Remaining Ride", false);
        isValid = false;
        return false;
      }

      if (!writeExpiryTime()) {
        Utilities.log("Unable to Write Expiry time", true);
        isValid = false;
        return false;
      }

      if (!writeMAC(MAC_PAGE)) {
        Utilities.log("Unable to Write MAC", true);
        isValid = false;
        return false;
      }
    }

    int counter = getCounterValue();
    setInfoToShow("Remaining rides: "
            +(getRemainingUses() - readCounterValue())
            + "\nExpiry time: "
            + convertIntToDate(getExpiryTime()));

    if (!enableProtection()) {
      isValid = false;
      Utilities.log("Enabling protection failed", true);
      return false;
    }
    return true;
  }

  /** Use ticket once */
  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  public boolean use() throws GeneralSecurityException, IOException {
    if (utils.authenticate(defaultAuthenticationKey)) {
      Utilities.log("Card is blank", true);
      setCustomerInfoToShow("Card is blank.");
      return false;
    }

    authenticationKey = getAuthenticationKey();
    boolean res = utils.authenticate(authenticationKey);
    if (!res) {
      Utilities.log("Authentication failed", true);
      setInfoToShow("Card authentication failed");
      return false;
    }

   Utilities.log(
            "Counter value: "
            + getCounterValue()
            + " - Counter value from page: "
            + getCounterFromPage(), false);

    if (isFirstTimeUse()) {
      expiryTime = calculateExpiryTime();

      if (!writeExpiryTime()) {
        isValid = false;
        Utilities.log("Unable to write expiry time", true);
        setCustomerInfoToShow("Something went wrong.");
        return false;
      }

      if (!writeMAC(MAC_PAGE)) {
        isValid = false;
        Utilities.log("Unable to write MAC", true);
        setCustomerInfoToShow("Something went wrong.");
        return false;
      }

      if (!increaseCounter()) {
        isValid = false;
        Utilities.log("Unable to increase counter", true);
        setCustomerInfoToShow("Something went wrong.");
        return false;
      }

      if (hasExceededRemainingUses()) {
        Utilities.log("Has exceeded remaining uses: " + hasExceededRemainingUses(), false);
        Utilities.log("Has exceeded remaining uses: ", true);
        setInfoToShow("You have exceeded your remaining rides");

        if (!resetCard()) {
          Utilities.log("Unable to reset exceeded card", true);
        }
        return false;
      }

      setInfoToShow("Remaining rides: "
              + (getRemainingUses() - counter)
              + "\nExpires in: "
              + convertIntToDate(getExpiryTime())
              );
      return true;
    }

    if (isDataIncorrect()) {
      return false;
    }

    if (!increaseCounter()) {
      Utilities.log("Unable to increase counter", true);
      setCustomerInfoToShow("Something went wrong.");
      return true;
    }

    setInfoToShow(
        "Remaining rides: "
            + (getRemainingUses() - readCounterValue())
            + "\nExpires in: "
            + convertIntToDate(getExpiryTime())
            );
    return true;
  }

  private boolean isFirstTimeUse() {
    return getCounterValue() == getCounterFromPage();
  }

  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private boolean isDataIncorrect() throws GeneralSecurityException, IOException {
    if (!isMACCorrect()) {
      Utilities.log("MAC incorrect", true);
      byte[] readMAC = readMAC(BACKUP_MAC_PAGE);
      byte[] calculatedMAC = calculateMAC();

      if (!(Arrays.equals(readMAC, calculatedMAC))) {
        setInfoToShow("Invalid MAC on card.");
        return true;
      }
    }

    if (areAllRidesUsed()) {
      Utilities.log("All uses used", true);
      setInfoToShow("Rides used up!");
      return true;
    }

    if (hasExceededRemainingUses()) {
      Utilities.log("Remaining uses have been exceeded.", false);
      Utilities.log("Remaining uses have been exceeded.", true);
      setInfoToShow("Remaining uses have been exceeded.");
      return true;
    }

    if (isExpired()) {
      Utilities.log("Your card has expired", true);
      setInfoToShow("Your card has expired.");
      return true;
    }

    if (hasExpiryTimeExceeded()) {
      Utilities.log("Expiry time has exceeded.", true);
      setCustomerInfoToShow("Expiry time has exceeded.");
      return true;
    }

    return false;
  }

  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private boolean resetCard() throws GeneralSecurityException, IOException {
    utils.eraseMemory();
    if (!resetAuthenticationKey()) {
      Utilities.log("Unable to reset authentication key", true);
      setInfoToShow("Unable to reset authentication key");
      return false;
    }
    return true;
  }
}
