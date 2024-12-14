import numpy as np
import cv2
import struct
import os
import shutil

# Dictionary to store statistics for each category of sizes
size_stats = {
    "Less than 10KB": [],
    "10-30KB": [],
    "30-60KB": [],
    "60-100KB": [],
    "100-200KB": [],
    "200-500KB": [],
    "500-1000KB": [],
    "Greater than or equal to 1000KB": []
}

def process_image(input_file_name):
    global size_stats
    
    # Read the whole file to data
    with open(input_file_name, 'rb') as binary_file:        
        data = binary_file.read()

    # Convert data to NumPy array
    d = np.frombuffer(data, dtype=np.uint8)

    # Data length in bytes
    data_len = len(data)

    # Determine image width based on file size range
    if data_len < 10 * 1024:  # Less than 10KB
        width = 32
        size_category = "Less than 10KB"
    elif 10 * 1024 <= data_len < 30 * 1024:  # 10-30KB
        width = 64
        size_category = "10-30KB"
    elif 30 * 1024 <= data_len < 60 * 1024:  # 30-60KB
        width = 128
        size_category = "30-60KB"
    elif 60 * 1024 <= data_len < 100 * 1024:  # 60-100KB
        width = 256
        size_category = "60-100KB"
    elif 100 * 1024 <= data_len < 200 * 1024:  # 100-200KB
        width = 384
        size_category = "100-200KB"
    elif 200 * 1024 <= data_len < 500 * 1024:  # 200-500KB
        width = 512
        size_category = "200-500KB"
    elif 500 * 1024 <= data_len < 1000 * 1024:  # 500-1000KB
        width = 768
        size_category = "500-1000KB"
    else:  # Greater than or equal to 1000KB
        width = 1024
        size_category = "Greater than or equal to 1000KB"

    # Calculate height based on the width and data length
    height = int(np.ceil(data_len / width))

    # Calculate the number of elements needed to pad the array to match the desired size
    num_pad_elements = width * height - data_len

    # Pad the array with zeros if necessary
    if num_pad_elements > 0:
        d = np.concatenate((d, np.zeros(num_pad_elements, dtype=np.uint8)))

    # Reshape data into 2D array with width as specified and height as calculated
    im = np.reshape(d, (height, width))

    # Create the image
    canvas = im.astype(np.uint8)

    # Save the image
    output_file_name = os.path.join(output_folder, os.path.basename(os.path.splitext(input_file_name)[0] + '_processed.png'))
    cv2.imwrite(output_file_name, canvas)

    # Update size stats
    size_stats[size_category].append((width, height))

    print(f"Processed: {input_file_name} -> {output_file_name}")
    return canvas, output_file_name


# Specify the path to the folder containing the PE files
folder_path = r"C:\Users\User\Desktop\Diploma\Executables"  # Use raw string to prevent escape sequences

# Specify the output directory
output_folder = r"C:\Users\User\Desktop\Diploma\Images"  # Use raw string to prevent escape sequences


# Create the output directory if it doesn't exist
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# Iterate over all files in the folder and process each image
for root, dirs, files in os.walk(folder_path):
    for file in files:
        file_path = os.path.join(root, file)
        # Process the image
        im_resized, output_file_name = process_image(file_path)
        # Move the processed image to the output directory
        shutil.move(output_file_name, os.path.join(output_folder, os.path.basename(output_file_name)))
        print(f"Moved: {output_file_name} -> {os.path.join(output_folder, os.path.basename(output_file_name))}")

# Print statistics
print("Size Statistics:")
for category, sizes in size_stats.items():
    num_images = len(sizes)
    if num_images > 0:
        avg_width = sum(size[0] for size in sizes) / num_images
        avg_height = sum(size[1] for size in sizes) / num_images
        print(f"{category}: {num_images} images, Avg Width: {avg_width:.2f}, Avg Height: {avg_height:.2f}")
    else:
        print(f"{category}: No images processed")