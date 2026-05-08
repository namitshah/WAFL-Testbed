import os

import torch
import torchvision.io as io
from PIL import Image
from torch.utils.data import Dataset


class FromSubsetDataset(Dataset):  # subset -> dataset
    def __init__(self, data_list, device, transform=None, useGPUinTrans=None):
        new_data_list = []
        for i in range(len(data_list)):
            image, label = data_list[i]
            if useGPUinTrans is True:
                label = torch.tensor(label).to(device)
            elif useGPUinTrans is False:
                label = torch.tensor(label)
            new_data_list.append([image, label])
        self.transform = transform
        self.data_list = new_data_list

    def __getitem__(self, index):
        data, label = self.data_list[index]
        if self.transform is not None:
            data = self.transform(data)
        return data, label

    def __len__(self):
        return len(self.data_list)


class MyGPUdataset(Dataset):
    """
    Optimized GPU Dataset:
    Loads only the specified indices into VRAM to save 90% of I/O and compute
    when dealing with agent-specific subsets.
    """

    def __init__(self, root, device, n_output, indices, transform=None, pre_transform=None):
        self.data = []
        self.labels = []
        self.transform = transform

        # 1. Build a manifest of all available file paths and labels
        # This is a 'virtual' list and doesn't load actual images yet.
        all_filepaths = []
        all_labels = []

        for i in range(0, n_output):
            folder_dir = os.path.join(root, str(i))
            if not os.path.exists(folder_dir):
                continue

            for image_name in os.listdir(folder_dir):
                all_filepaths.append(os.path.join(folder_dir, image_name))
                all_labels.append(i)

        # 2. Filter the manifest using the provided indices
        # This is where the 90% reduction in work happens.
        if indices is not None:
            target_files = [all_filepaths[idx] for idx in indices]
            target_labels = [all_labels[idx] for idx in indices]
        else:
            target_files = all_filepaths
            target_labels = all_labels
        # 3. Only perform heavy I/O and GPU transfer for the subset
        for full_path, label in zip(target_files, target_labels):
            # Load and move to GPU
            image_buf = io.read_image(full_path).to(device)

            # Apply pre-processing (resizing, etc.) while on GPU
            if pre_transform is not None:
                image_buf = pre_transform(image_buf)

            self.data.append(image_buf)
            self.labels.append(torch.tensor(label).to(device))
        print(f"Images Loaded: {len(self.data)} | Type {'Train' if indices is not None else 'Test'}")

    def __getitem__(self, index):
        data = self.data[index]
        label = self.labels[index]
        if self.transform is not None:
            data = self.transform(data)
        return data, label

    def __len__(self):
        return len(self.data)


class Mydataset(Dataset):  # Custom Dataset to load the images to GPU in advance.
    def __init__(self, root, n_output, transform=None):
        self.img_paths = []
        self.labels = []
        self.transform = transform
        for i in range(0, n_output):  # i: label
            dir = os.path.join(root, str(i))
            images_path = os.listdir(dir)
            for image_path in images_path:
                full_path = os.path.join(dir, image_path)
                self.img_paths.append(full_path)
                self.labels.append(i)  # send the label to GPU as well

    def __getitem__(self, index):
        img_path = self.img_paths[index]
        data = Image.open(img_path).convert("RGB")
        label = self.labels[index]
        if self.transform is not None:
            data = self.transform(data)
        return data, label

    def __len__(self):
        return len(self.img_paths)
