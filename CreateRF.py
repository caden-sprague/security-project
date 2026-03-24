import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def createRF():
    print("======= Creating RF =======")
    
    # Load attack and normal traffic CSVs and merge into one DataFrame,
    # filling missing values with 0 to avoid NaN errors during training
    files = [
        "ICUDatasetProcessed/Attack.csv",
        "ICUDatasetProcessed/environmentMonitoring.csv",
        "ICUDatasetProcessed/patientMonitoring.csv"
    ]

    frames = []

    for csv in files:
        df = pd.read_csv(csv, low_memory=False)
        df.fillna(0, inplace=True)
        frames.append(df)

    df1 = pd.concat(frames, ignore_index=True)

    # Select the 10 features chosen in the paper plus the target label
    fs2 = [
        'frame.time_delta',
        'tcp.time_delta',
        'tcp.flags.ack',
        'tcp.flags.push',
        'tcp.flags.reset',
        'mqtt.hdrflags',
        'mqtt.msgtype',
        'mqtt.qos',
        'mqtt.retain',
        'mqtt.ver',
        'label'
    ]

    df1 = df1[fs2]

    # mqtt.hdrflags contains hex strings; convert to integers so the model can use them
    label_encoder = LabelEncoder()
    df1['mqtt.hdrflags'] = label_encoder.fit_transform(df1['mqtt.hdrflags'])

    # Split into 70% train / 30% test; random_state=100 ensures reproducibility
    X_train, X_test, y_train, y_test = train_test_split(
        df1.drop(labels=['label'], axis=1),
        df1['label'],
        test_size=0.3,
        random_state=100
    )

    # Train a Random Forest with max depth 10 to limit overfitting
    RF = RandomForestClassifier(max_depth=10, random_state=100)
    RF.fit(X_train, y_train)

    # Save the trained model and test set to disk for use in other scripts
    joblib.dump({"model": RF, "X_test": X_test, "y_test": y_test, "hdrflags_encoder": label_encoder}, "rf_model.pkl")

    return RF, X_test, y_test

if (__name__ == "__main__"):
    # Train and save if no saved model exists, otherwise load from disk
    if not os.path.exists("rf_model.pkl"):
        RF, X_test, y_test = createRF()
    else:
        saved = joblib.load("rf_model.pkl")
        RF, X_test, y_test = saved["model"], saved["X_test"], saved["y_test"]

    print("======= TESTING RF =======")

    # Run the trained model on the held-out test set
    RF_prediction = RF.predict(X_test)

    # Print classification metrics (multiplied by 100 to display as percentages)
    print("Accuracy:", accuracy_score(y_test, RF_prediction) * 100)
    print("Precision:", precision_score(y_test, RF_prediction) * 100)
    print("Recall:", recall_score(y_test, RF_prediction) * 100)
    print("F1-score:", f1_score(y_test, RF_prediction) * 100)
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, RF_prediction))