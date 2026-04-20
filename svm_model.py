import pandas as pd
import os

# =========================
# 1. LOAD DATASET
# =========================
path = 'ICUDatasetProcessed/'
csvs = os.listdir(path)

df = pd.DataFrame()

for file in csvs:
    print(f"Reading {file}")
    temp = pd.read_csv(os.path.join(path, file))
    temp.fillna(0, inplace=True)
    df = pd.concat([df, temp], ignore_index=True)

print("Dataset shape:", df.shape)


# =========================
# 2. DROP UNUSED FEATURES
# =========================
drop_cols = ['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
             'mqtt.topic', 'mqtt.msg', 'tcp.payload',
             'mqtt.clientid', 'mqtt.conflags', 'mqtt.conack.flags', 'class']

df.drop(columns=drop_cols, inplace=True)


# =========================
# 3. SELECT SAME FEATURES
# =========================
features = ['frame.time_delta', 'tcp.time_delta', 'tcp.flags.ack',
            'tcp.flags.push', 'tcp.flags.reset', 'mqtt.hdrflags',
            'mqtt.msgtype', 'mqtt.qos', 'mqtt.retain', 'mqtt.ver', 'label']

df = df[features]


# =========================
# 4. ENCODE DATA
# =========================
from sklearn.preprocessing import LabelEncoder

le = LabelEncoder()
df['mqtt.hdrflags'] = le.fit_transform(df['mqtt.hdrflags'])


# =========================
# 5. TRAIN TEST SPLIT
# =========================
from sklearn.model_selection import train_test_split

X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=100
)


# =========================
# 6. TRAIN SVM MODEL
# =========================
from sklearn.svm import SVC

print("\nTraining SVM model...")

svm_model = SVC()
svm_model.fit(X_train, y_train)

pred = svm_model.predict(X_test)


# =========================
# 7. EVALUATION
# =========================
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

accuracy = accuracy_score(y_test, pred)
precision = precision_score(y_test, pred)
recall = recall_score(y_test, pred)
f1 = f1_score(y_test, pred)

print("\n=== SVM RESULTS ===")
print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1 Score: {f1:.4f}")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, pred))


# =========================
# 8. FALSE POSITIVES
# =========================
false_positives = ((y_test == 0) & (pred == 1)).sum()
print("\nFalse Positives:", false_positives)
