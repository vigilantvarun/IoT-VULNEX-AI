
import requests
import time
import json
import random

# ==========================================
# IOT VULNEX AI - COLLEGE DEMO SIMULATOR
# ==========================================

API_URL = "http://127.0.0.1:5000/api/telemetry"

DEVICE_CODE = "ESP32_001"


# ==========================================
# NORMAL SENSOR READINGS
# ==========================================

normal_readings = [
    {
        "temperature": 27,
        "humidity": 50,
        "network_rate": 45,
        "failed_logins": 0
    },
    {
        "temperature": 28,
        "humidity": 48,
        "network_rate": 55,
        "failed_logins": 0
    },
    {
        "temperature": 26,
        "humidity": 52,
        "network_rate": 40,
        "failed_logins": 1
    },
    {
        "temperature": 29,
        "humidity": 49,
        "network_rate": 50,
        "failed_logins": 0
    }
]


# ==========================================
# SUSPICIOUS SENSOR READINGS
# ==========================================

suspicious_readings = [
    {
        "temperature": 90,
        "humidity": 95,
        "network_rate": 950,
        "failed_logins": 20
    },
    {
        "temperature": 85,
        "humidity": 90,
        "network_rate": 850,
        "failed_logins": 15
    },
    {
        "temperature": 95,
        "humidity": 98,
        "network_rate": 1000,
        "failed_logins": 25
    }
]


# ==========================================
# SEND SENSOR DATA TO FLASK
# ==========================================

def send_sensor_data(reading):

    payload = {
        "device_code": DEVICE_CODE,
        **reading
    }

    try:

        response = requests.post(
            API_URL,
            json=payload,
            timeout=10
        )

        print("\n----------------------------------")
        print("IOT VULNEX AI - DEVICE REPORT")
        print("----------------------------------")

        print("Device:", DEVICE_CODE)
        print("Sensor Data:", reading)

        print("HTTP Status:", response.status_code)

        if response.ok:

            result = response.json()

            print("\nAI ANALYSIS:")

            print(json.dumps(
                result["ai_analysis"],
                indent=4
            ))

            return True

        else:

            print("Server Error:", response.text)

            return False

    except requests.RequestException as error:

        print("\nConnection Error:", error)

        print("Make sure Flask is running.")

        return False


# ==========================================
# RUN SELECTED SIMULATION
# ==========================================

def run_simulation(readings, mode_name):

    print("\n==================================")
    print("IOT VULNEX AI - COLLEGE DEMO MODE")
    print("==================================")

    print("Device:", DEVICE_CODE)
    print("Simulation:", mode_name)
    print("Total Readings:", len(readings))

    successful = 0

    for number, reading in enumerate(readings, start=1):

        print(
            f"\nSending reading {number} of {len(readings)}"
        )

        if send_sensor_data(reading):
            successful += 1

        time.sleep(2)

    print("\n==================================")
    print("SIMULATION COMPLETED")
    print("==================================")

    print("Successful readings:", successful)
    print("Failed readings:", len(readings) - successful)


# ==========================================
# RANDOM LIVE SIMULATION
# ==========================================

def run_live_simulation():

    print("\nStarting live virtual IoT simulation.")
    print("Press Ctrl + C to stop.")

    try:

        while True:

            reading = {
                "temperature": round(random.uniform(24, 32), 2),
                "humidity": round(random.uniform(40, 60), 2),
                "network_rate": round(random.uniform(30, 80), 2),
                "failed_logins": random.choice([0, 0, 0, 1])
            }

            send_sensor_data(reading)

            time.sleep(3)

    except KeyboardInterrupt:

        print("\nLive simulation stopped.")


# ==========================================
# COLLEGE DEMO MENU
# ==========================================

def main():

    while True:

        print("\n")
        print("======================================")
        print("       IOT VULNEX AI")
        print("       COLLEGE DEMO MODE")
        print("======================================")

        print("1. Normal IoT Simulation")
        print("2. Suspicious Activity Simulation")
        print("3. Complete AI Demonstration")
        print("4. Live Random IoT Simulation")
        print("5. Exit")

        choice = input("\nSelect an option (1-5): ").strip()

        if choice == "1":

            run_simulation(
                normal_readings,
                "Normal IoT Activity"
            )

        elif choice == "2":

            run_simulation(
                suspicious_readings,
                "Suspicious IoT Activity"
            )

        elif choice == "3":

            complete_demo = (
                normal_readings + suspicious_readings
            )

            run_simulation(
                complete_demo,
                "Complete AI Security Demonstration"
            )

        elif choice == "4":

            run_live_simulation()

        elif choice == "5":

            print("\nCollege Demo Mode closed.")

            break

        else:

            print("\nInvalid option. Select 1 to 5.")


if __name__ == "__main__":

    main()
