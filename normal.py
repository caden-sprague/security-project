"generate normal traffic"
import time
import random
import paho.mqtt.client as mqtt

BROKER = "localhost"
TOPIC = "icu/heart_rate"

client = mqtt.Client()
client.connect(BROKER, 1883, 60)

try:
    while True:
        heart_rate = random.randint(60, 79)  # same as 60 + RANDOM % 20
        message = str(heart_rate)

        client.publish(TOPIC, message)
        print(f"Sent: {message}")

        time.sleep(2)

except KeyboardInterrupt:
    print("Stopped")
    client.disconnect()