"generate normal traffic"
import paho.mqtt.client as mqtt

BROKER = "localhost"
TOPIC = "icu/heart_rate"

client = mqtt.Client()
client.connect(BROKER, 1883, 60)

try:
    while True:
        # Abnormal value + high frequency (no sleep)
        client.publish(TOPIC, "999")

except KeyboardInterrupt:
    print("Stopped")
    client.disconnect()