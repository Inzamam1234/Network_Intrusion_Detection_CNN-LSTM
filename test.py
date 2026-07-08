from tensorflow import keras

model = keras.models.load_model(
    "models/cnn_ids_model.h5",
    compile=False
)

print("SUCCESS")