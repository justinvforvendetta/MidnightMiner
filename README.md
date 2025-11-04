# Midnight Miner

A Python-based mining bot for the Midnight Network's scavenger hunt, allowing users to automatically mine for NIGHT tokens with multiple wallets.

**Cross-platform compatible**: Works on Windows, Linux, and macOS.

If you are unfamiliar with python, check out the [Easy Guide](EasyGuide.md).

## Disclaimer

This is an unofficial tool, and has not been properly tested. Use it at your own risk.

I will be updating and improving this software regularly. Please keep up to date by re-downloading from this repository and copying over your `wallets.json` and `challenges.json` files, or simply by running `git pull`. 

## How It Works

The miner operates by performing the following steps:
1.  **Wallet Setup**: It creates or loads several Cardano wallets to be used for mining. These wallets are stored in `wallets.json`.
2.  **Registration**: The bot registers the wallets with the Midnight Scavenger Mine API and agrees to the terms and conditions.
3.  **Challenge Loop**: It continuously polls the API for new mining challenges. Challenges are stored in `challenges.json` so they can be resumed later.
4.  **Mining**: When a new challenge is received, the bot uses the provided parameters to build a large proof-of-work table (ROM). It then rapidly searches for a valid nonce that solves the challenge's difficulty requirement. The core hashing logic is performed by a WebAssembly module (`ashmaize_web_bg.wasm`) for performance.
5.  **Submission**: Once a solution is found, it is submitted to the API to earn NIGHT tokens.

## Prerequisites

Before running the miner, ensure you have the following:

1.  **Python 3**: The script is written in Python (version 3.8 or higher recommended).
2.  **Required Libraries**: Install the necessary Python packages using pip:
    ```bash
    pip install wasmtime requests pycardano cbor2 portalocker
    ```
3. **Git**: Use Git to download and update your Miner easily.

## Download

Run this command to download MidnightMiner
```
git clone https://github.com/djeanql/MidnightMiner && cd MidnightMiner
```

## Usage

You can run the miner from your terminal.

-   **Start mining**:
    This command will either load an existing wallet from `wallets.json` or create a new one if it doesn't exist.
    ```bash
    python miner.py
    ```

-   **Multiple workers/wallets**:
    To mine with multiple wallets, use:
    ```bash
    python miner.py --workers <number of workers>
    ```
    Each worker typically uses one CPU core, and 1GB of RAM. Do not run more workers than your system is capable of.


## ⚠️ Update Regularly

This software will be updated very frequently, so it is important you update it to earn the highest rewards. To update, run this command in the MidnightMiner directory:
```
git pull
```

I suggest running this once a day to make sure your miner is up-to-date.


## Developer Donations

This miner includes an **optional 5% donation system** to support ongoing development and maintenance. By default, approximately 1 in 20 (5%) of solved challenges will be mined for the developer's address.

Thank you for considering supporting this project!

To disable donations, add the `--no-donation` flag:
```bash
python miner.py --no-donation
```


## Exporting Wallets

To access your earned NIGHT tokens, you will need to import your wallets' signing keys (`.skey` files) into a Cardano wallet like Eternl. The `export_skeys.py` script helps with this process.

1.  **Run the export script**:
    ```bash
    python export_skeys.py
    ```
    This will create a directory named `skeys/` (if it doesn't exist) and export each wallet's signing key from `wallets.json` into a separate `.skey` file (e.g., `skeys/wallet_0.skey`).

2.  **Import into Eternl (or other Cardano wallet)**:
    *   Open your Eternl wallet.
    *   Go to `Add Wallet` -> `More` -> `CLI Signing Keys`.
    *   Import the `.skey` files generated in the `skeys/` directory.

## Dashboard

The dashboard displays important information about the status of each worker. The `Challenge` column shows which challenge ID the worker is trying to solve. It also shows statuses if not actively mining, for example "Waiting" if all known challenges have been completed. `Completed` shows how many solutions have been sucessfully submitted (and verified) by the server. In brackets is the number of challenges solved since starting the miner. `NIGHT` is an estimation of the rewards each wallet will receive. This is updated every 24 hours.

If developer donations are enabled (default), when a worker is mining for the developer, the `Address` field for that worker will temporarily show **"developer"** instead of the wallet address.

```
==============================================================================================================
                                    MIDNIGHT MULTI-WALLET MINER DASHBOARD
==============================================================================================================
Active Workers: 6 | Last Update: 2025-11-03 19:22:11
==============================================================================================================

ID   Address                                      Challenge            Attempts   H/s      Completed  NIGHT
--------------------------------------------------------------------------------------------------------------
0    addr1vxask5vpp8p4xddsc3qd63luy4ecf67233...   **D05C02             470,000    204      4          0
1    developer (thank you!)                       **D05C19             471,000    204      8          7.043
2    addr1v9hcpxeevkks7g4mvyls029yuvvsm0dfzl...   **D05C20             48,000     203      5          0
3    addr1vx64c8703ketwnjtxkjcqzsktwkcvhve7f...   **D05C20             154,000    203      7          3.522
4    addr1vxh3ckvkena0hzm24fhj9ac9ezrjz5ufju...   **D05C03             20,000     203      5          0
5    addr1v8ugwtuwyqwh42ejd5af6f5tvzpjt4m5r2...   **D05C18             316,000    203      2          0
--------------------------------------------------------------------------------------------------------------
TOTAL                                                                              1221     31         10.565
==============================================================================================================

Press Ctrl+C to stop all miners
```

