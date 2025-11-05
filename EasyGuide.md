# Easy Guide to Running Midnight Miner on Windows

This guide will help you start mining NIGHT tokens on Windows with MidnightMiner. If you have any questions, you can post them [here](https://www.reddit.com/r/Midnight/comments/1onpvk5/comment/nn40j1r/) or message @djeanql on Discord.

## What This Software Does

Midnight Miner automatically solves puzzles to earn NIGHT tokens. It runs on your computer using multiple workers that rotate through different wallets to earn more rewards. Each worker uses its own unique wallet, and new wallets are created automatically as needed.

## Step 1: Install Python

Python is the programming language this software runs on.

1. Go to [python.org/downloads](https://www.python.org/downloads/)
2. Download 3.13.x for windows
4. Click "Install Now" and click through the steps (no need to change any config)
5. Wait for installation to complete

Alternatively, you can install [Python 3.13](https://apps.microsoft.com/detail/9pnrbtzxmb4z) from the Microsoft store.

## Step 2: Install Git

Git allows for the miner to be easily downloaded and updated from the terminal.

1. Go to [git-scm.com/install/windows](https://git-scm.com/install/windows)
2. Download the standalone installer (x64)
3. Run the installer and click through steps, leave all the configuration options as-is

## Step 3: Download MidnightMiner

1. Open Command Prompt:
   - Press `Windows`
   - Type `cmd` and press Enter
2. Type `git clone https://github.com/djeanql/MidnightMiner`
3. Then enter the folder with `cd MidnightMiner`

## Step 4: Install Dependencies


Install the required dependencies by typing:
   ```
   pip install requests pycardano cbor2 portalocker
   ```
Press Enter and wait for installation to finish

If you get a command not found error, you can use `python -m pip` instead of `pip`

## Step 5: Start Mining

**For a single worker** (good for testing):
```
python miner.py
```

**For multiple workers** (recommended for better earnings):
```
python miner.py --workers 4
```

Replace `4` with the number of workers you want to use. Each worker uses roughly one CPU core and about 1GB of memory. The miner will automatically create enough wallets for all workers and rotate through them as puzzles are completed.

> **Tip**: If you have a 6-core processor, try `--workers 6`.

## ⚠️ Update Regularly

This software will be updated very frequently, so it is important you update it to earn the highest rewards. To update, run this command while in the MidnightMiner folder:
```
git pull
```

This will fetch any changes made in this repository

## Back Up Your Wallet File

It is important that you back up `wallets.json`, which is in the same folder as the miner. Copy it to a safe location. The miner automatically creates new wallets as needed, so you should back up this file regularly to ensure you don't lose access to any earned tokens.

## The Dashboard

Once running, you'll see a dashboard that updates automatically. Each row shows one worker (workers rotate through different wallets automatically):

- **ID**: Worker number
- **Address**: The wallet address currently being used by this worker
- **Challenge**: The puzzle being solved (or status like "Building ROM" or "Waiting")
- **Attempts**: How many guesses have been tried
- **H/s**: Guesses per second (hash rate)

At the bottom, you'll see totals across all your wallets:
- **Total Hash Rate**: Combined speed of all workers
- **Total Completed**: Total puzzles solved (number in brackets shows puzzles solved this session)
- **Total NIGHT**: Estimated token rewards across all wallets (fetched once at startup)

Press `Ctrl+C` to stop the miner anytime.

## Claiming NIGHT

You will need to claim your NIGHT tokens with the wallets created by the software. To access them:

1. Export your wallet keys by running:
   ```
   python export_skeys.py
   ```

2. This creates a `skeys` folder with wallet files

3. Import these files into a Cardano wallet (like Eternl):
   - Open Eternl wallet
   - Go to Add Wallet -> More -> CLI Signing Keys
   - Select the files from the `skeys` folder
