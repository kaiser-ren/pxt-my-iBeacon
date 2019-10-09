



#include "MicroBitConfig.h"
#include "MicroBitBLEManager.h"
#include "MicroBitEddystone.h"
#include "MicroBitStorage.h"
#include "MicroBitFiber.h"
#include "MicroBitSystemTimer.h"
#include "MicroBitIBeacon.h"

/* The underlying Nordic libraries that support BLE do not compile cleanly with the stringent GCC settings we employ.
 * If we're compiling under GCC, then we suppress any warnings generated from this code (but not the rest of the DAL)
 * The ARM cc compiler is more tolerant. We don't test __GNUC__ here to detect GCC as ARMCC also typically sets this
 * as a compatability option, but does not support the options used...
 */
#if !defined(__arm)
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

#include "ble.h"

extern "C" {
#include "device_manager.h"
uint32_t btle_set_gatt_table_size(uint32_t size);
}

/*
 * Return to our predefined compiler settings.
 */
#if !defined(__arm)
#pragma GCC diagnostic pop
#endif

#define MICROBIT_PAIRING_FADE_SPEED 4

// Some Black Magic to compare the definition of our security mode in MicroBitConfig with a given parameter.
// Required as the MicroBitConfig option is actually an mbed enum, that is not normally comparable at compile time.
//

#define __CAT(a, ...) a##__VA_ARGS__


const char *MICROBIT_BLE_MANUFACTURER = NULL;
const char *MICROBIT_BLE_MODEL = "BBC micro:bit";
const char *MICROBIT_BLE_HARDWARE_VERSION = NULL;
const char *MICROBIT_BLE_FIRMWARE_VERSION = MICROBIT_DAL_VERSION;
const char *MICROBIT_BLE_SOFTWARE_VERSION = NULL;
const int8_t MICROBIT_BLE_POWER_LEVEL[] = {-30, -20, -16, -12, -8, -4, 0, 4};

/*
 * Many of the mbed interfaces we need to use only support callbacks to plain C functions, rather than C++ methods.
 * So, we maintain a pointer to the MicroBitBLEManager that's in use. Ths way, we can still access resources on the micro:bit
 * whilst keeping the code modular.
 */
MicroBitBLEManager *MicroBitBLEManager::manager = NULL; // Singleton reference to the BLE manager. many mbed BLE API callbacks still do not support member funcions yet. :-(



/**
 * Constructor.
 * Configure and manage the micro:bit's Bluetooth Low Energy (BLE) stack.
 * @param _storage an instance of MicroBitStorage used to persist sys attribute information. (This is required for compatability with iOS).
 * @note The BLE stack *cannot*  be brought up in a static context (the software simply hangs or corrupts itself).
 * Hence, the init() member function should be used to initialise the BLE stack.
 */
MicroBitBLEManager::MicroBitBLEManager(MicroBitStorage &_storage) : storage(&_storage)
{
    manager = this;
    this->ble = NULL;
    this->pairingStatus = 0;
}

/**
 * Constructor.
 * Configure and manage the micro:bit's Bluetooth Low Energy (BLE) stack.
 * @note The BLE stack *cannot*  be brought up in a static context (the software simply hangs or corrupts itself).
 * Hence, the init() member function should be used to initialise the BLE stack.
 */
MicroBitBLEManager::MicroBitBLEManager() : storage(NULL)
{
    manager = this;
    this->ble = NULL;
    this->pairingStatus = 0;
}

/**
 * When called, the micro:bit will begin advertising for a predefined period,
 * MICROBIT_BLE_ADVERTISING_TIMEOUT seconds to bonded devices.
 */
MicroBitBLEManager *MicroBitBLEManager::getInstance()
{
    if (manager == 0)
    {
        manager = new MicroBitBLEManager;
    }
    return manager;
}

/**
 * When called, the micro:bit will begin advertising for a predefined period,
 * MICROBIT_BLE_ADVERTISING_TIMEOUT seconds to bonded devices.
 */
void MicroBitBLEManager::advertise()
{
    if (ble)
        ble->gap().startAdvertising();
}

/**
  * Post constructor initialisation method as the BLE stack cannot be brought
  * up in a static context.
  * @param deviceName The name used when advertising
  * @param serialNumber The serial number exposed by the device information service
  * @param messageBus An instance of an EventModel, used during pairing.
  * @param enableBonding If true, the security manager enabled bonding.
  * @code
  * bleManager.init(uBit.getName(), uBit.getSerial(), uBit.messageBus, true);
  * @endcode
  */
void MicroBitBLEManager::init(ManagedString deviceName, ManagedString serialNumber, EventModel &messageBus, bool enableBonding)
{
    ManagedString BLEName("BBC micro:bit");
    this->deviceName = deviceName;

//wlw #if !(CONFIG_ENABLED(MICROBIT_BLE_WHITELIST))
    ManagedString namePrefix(" [");
    ManagedString namePostfix("]");
    BLEName = BLEName + namePrefix + deviceName + namePostfix;
//wlw #endif

// Start the BLE stack.
#if CONFIG_ENABLED(MICROBIT_HEAP_REUSE_SD)
    btle_set_gatt_table_size(MICROBIT_SD_GATT_TABLE_SIZE);
#endif

    ble = new BLEDevice();
    ble->init();


    // Configure the stack to hold onto the CPU during critical timing events.
    // mbed-classic performs __disable_irq() calls in its timers that can cause
    // MIC failures on secure BLE channels...
    ble_common_opt_radio_cpu_mutex_t opt;
    opt.enable = 1;
    sd_ble_opt_set(BLE_COMMON_OPT_RADIO_CPU_MUTEX, (const ble_opt_t *)&opt);



    // Configure the radio at our default power level
//    setTransmitPower(MICROBIT_BLE_DEFAULT_TX_POWER);
    // use higher power setting for iOS nrf Connect
    setTransmitPower(6);

// Bring up core BLE services.
#if CONFIG_ENABLED(MICROBIT_BLE_DFU_SERVICE)
    new MicroBitDFUService(*ble);
#endif

#if CONFIG_ENABLED(MICROBIT_BLE_DEVICE_INFORMATION_SERVICE)
    DeviceInformationService ble_device_information_service(*ble, MICROBIT_BLE_MANUFACTURER, MICROBIT_BLE_MODEL, serialNumber.toCharArray(), MICROBIT_BLE_HARDWARE_VERSION, MICROBIT_BLE_FIRMWARE_VERSION, MICROBIT_BLE_SOFTWARE_VERSION);
#else
    (void)serialNumber;
#endif

#if CONFIG_ENABLED(MICROBIT_BLE_EVENT_SERVICE)
    new MicroBitEventService(*ble, messageBus);
#else
    (void)messageBus;
#endif


// Setup advertising.
#if CONFIG_ENABLED(MICROBIT_BLE_WHITELIST)
    ble->accumulateAdvertisingPayload(GapAdvertisingData::BREDR_NOT_SUPPORTED);
#else
    ble->accumulateAdvertisingPayload(GapAdvertisingData::BREDR_NOT_SUPPORTED | GapAdvertisingData::LE_GENERAL_DISCOVERABLE);
#endif

    ble->accumulateAdvertisingPayload(GapAdvertisingData::COMPLETE_LOCAL_NAME, (uint8_t *)BLEName.toCharArray(), BLEName.length());
    ble->setAdvertisingType(GapAdvertisingParams::ADV_CONNECTABLE_UNDIRECTED);
    ble->setAdvertisingInterval(200);

#if (MICROBIT_BLE_ADVERTISING_TIMEOUT > 0)
    ble->gap().setAdvertisingTimeout(MICROBIT_BLE_ADVERTISING_TIMEOUT);
#endif
    ble->gap().startAdvertising();
}


/**
 * Change the output power level of the transmitter to the given value.
 * @param power a value in the range 0..7, where 0 is the lowest power and 7 is the highest.
 * @return MICROBIT_OK on success, or MICROBIT_INVALID_PARAMETER if the value is out of range.
 * @code
 * // maximum transmission power.
 * bleManager.setTransmitPower(7);
 * @endcode
 */
int MicroBitBLEManager::setTransmitPower(int power)
{
    if (power < 0 || power >= MICROBIT_BLE_POWER_LEVELS)
        return MICROBIT_INVALID_PARAMETER;

    if (ble->gap().setTxPower(MICROBIT_BLE_POWER_LEVEL[power]) != NRF_SUCCESS)
        return MICROBIT_NOT_SUPPORTED;

    return MICROBIT_OK;
}




/**
 * Periodic callback in thread context.
 * We use this here purely to safely issue a disconnect operation after a pairing operation is complete.
 */
void MicroBitBLEManager::idleTick()
{

}  


/**
* Stops any currently running BLE advertisements
*/
void MicroBitBLEManager::stopAdvertising()
{
    ble->gap().stopAdvertising();
}

#if CONFIG_ENABLED(MICROBIT_BLE_EDDYSTONE_URL)
/**
  * Set the content of Eddystone URL frames
  * @param url The url to broadcast
  * @param calibratedPower the transmission range of the beacon (Defaults to: 0xF0 ~10m).
  * @param connectable true to keep bluetooth connectable for other services, false otherwise. (Defaults to true)
  * @param interval the rate at which the micro:bit will advertise url frames. (Defaults to MICROBIT_BLE_EDDYSTONE_ADV_INTERVAL)
  * @note The calibratedPower value ranges from -100 to +20 to a resolution of 1. The calibrated power should be binary encoded.
  * More information can be found at https://github.com/google/eddystone/tree/master/eddystone-uid#tx-power
  */
int MicroBitBLEManager::advertiseEddystoneUrl(const char* url, int8_t calibratedPower, bool connectable, uint16_t interval)
{
    ble->gap().stopAdvertising();
    ble->clearAdvertisingPayload();

    ble->setAdvertisingType(connectable ? GapAdvertisingParams::ADV_CONNECTABLE_UNDIRECTED : GapAdvertisingParams::ADV_NON_CONNECTABLE_UNDIRECTED);
    ble->setAdvertisingInterval(interval);

    ble->accumulateAdvertisingPayload(GapAdvertisingData::BREDR_NOT_SUPPORTED | GapAdvertisingData::LE_GENERAL_DISCOVERABLE);

    int ret = MicroBitEddystone::getInstance()->setURL(ble, url, calibratedPower);

#if (MICROBIT_BLE_ADVERTISING_TIMEOUT > 0)
    ble->gap().setAdvertisingTimeout(MICROBIT_BLE_ADVERTISING_TIMEOUT);
#endif
    ble->gap().startAdvertising();
    
    return ret;
}

/**
  * Set the content of Eddystone URL frames, but accepts a ManagedString as a url.
  * @param url The url to broadcast
  * @param calibratedPower the transmission range of the beacon (Defaults to: 0xF0 ~10m).
  * @param connectable true to keep bluetooth connectable for other services, false otherwise. (Defaults to true)
  * @param interval the rate at which the micro:bit will advertise url frames. (Defaults to MICROBIT_BLE_EDDYSTONE_ADV_INTERVAL)
  * @note The calibratedPower value ranges from -100 to +20 to a resolution of 1. The calibrated power should be binary encoded.
  * More information can be found at https://github.com/google/eddystone/tree/master/eddystone-uid#tx-power
  */
int MicroBitBLEManager::advertiseEddystoneUrl(ManagedString url, int8_t calibratedPower, bool connectable, uint16_t interval)
{
    return advertiseEddystoneUrl((char *)url.toCharArray(), calibratedPower, connectable, interval);
}
#endif

/**
  * Set the content of Eddystone URL frames
  *
  * @param proximityUUID 16-byte proximity UUID
  *
  * @param major 2-byte major value
  *
  * @param minor 2-byte minor value
  *
  * @param calibratedPower the transmission range of the beacon (Defaults to: 0xF0 ~10m).
  *
  * @param interval the rate at which the micro:bit will advertise url frames. (Defaults to MICROBIT_BLE_EDDYSTONE_ADV_INTERVAL)
  *
  * @note The calibratedPower value ranges from -100 to +20 to a resolution of 1. The calibrated power should be binary encoded.
  * More information can be found at https://github.com/google/eddystone/tree/master/eddystone-uid#tx-power
  */
int MicroBitBLEManager::advertiseIBeacon(const UUID &proximityUUID, int16_t major, int16_t minor, int8_t calibratedPower, uint16_t interval)
{
    int retVal = MICROBIT_OK;

    ble->gap().stopAdvertising();
    ble->clearAdvertisingPayload();

    ble->setAdvertisingType(GapAdvertisingParams::ADV_NON_CONNECTABLE_UNDIRECTED);
    ble->setAdvertisingInterval(interval);

    ble->accumulateAdvertisingPayload(GapAdvertisingData::BREDR_NOT_SUPPORTED | GapAdvertisingData::LE_GENERAL_DISCOVERABLE);

    retVal = MicroBitIBeacon::getInstance()->setParams(ble, proximityUUID, major, minor, calibratedPower);

#if (MICROBIT_BLE_ADVERTISING_TIMEOUT > 0)
    ble->gap().setAdvertisingTimeout(MICROBIT_BLE_ADVERTISING_TIMEOUT);
#endif
    ble->gap().startAdvertising();

    return retVal;
}

 


