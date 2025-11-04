# Easy Guide to Running Midnight Miner on Windows

This guide will help you start mining NIGHT tokens on Windows.

## What This Software Does

Midnight Miner automatically solves puzzles to earn NIGHT tokens. It runs on your computer and can use multiple wallets at the same time to earn more rewards.

## Step 1: Install Python

Python is the programming language this software runs on.

1. Go to [python.org/downloads](https://www.python.org/downloads/)
2. Download the latest version for Windows
3. **Important**: When installing, check the box that says "Add Python to PATH"
4. Click "Install Now"
5. Wait for installation to complete

## Step 2: Download the Software

1. Download all the files from this repository to a folder on your computer ("Code" button on top right -> Download ZIP)
2. Extract the ZIP anywhere (for example: `C:\Users\YourName\Downloads\midnight_miner`)

## Step 3: Install Required Components

1. Open Command Prompt:
   - Press `Windows`
   - Type `cmd` and press Enter

2. Navigate to the folder where you saved the files:
   ```
   cd C:\Users\YourName\Downloads\midnight_miner
   ```
   (Replace with your actual folder path)

3. Install the required components by typing:
   ```
   pip install wasmtime requests pycardano cbor2 portalocker
   ```
   Press Enter and wait for installation to finish

## Step 4: Start Mining

**For a single wallet** (good for testing):
```
python miner.py
```

**For multiple wallets** (recommended for better earnings):
```
python miner.py --workers 4
```

Replace `4` with the number of wallets you want to use. Each wallet uses one CPU core and about 1GB of memory.

> **Tip**: If you have a 6-core processor, try `--workers 6`. Don't use more workers than you have CPU cores.

## Step 5: Understanding the Dashboard

Once running, you'll see a dashboard that updates automatically:

- **Address**: Your wallet addresses (where tokens are sent)
- **Challenge**: The puzzle being solved
- **Attempts**: How many guesses have been tried
- **H/s**: Guesses per second
- **Completed**: Number of puzzles solved
- **NIGHT**: Estimated token rewards

Press `Ctrl+C` to stop the miner anytime.

## Step 6: Accessing Your Tokens

Your earned tokens are stored in wallets created by the software. To access them:

1. Export your wallet keys by running:
   ```
   python export_skeys.py
   ```

2. This creates a `skeys` folder with wallet files

3. Import these files into a Cardano wallet (like Eternl):
   - Open Eternl wallet
   - Go to Add Wallet -> More -> CLI Signing Keys
   - Select the files from the `skeys` folder

## Updating the Software

To get the latest improvements:

1. Download the new files from github
2. Copy over your `wallets.json` and `challenges.json` files into the new folder
3. Restart the miner


