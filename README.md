# Midnight Miner

A Python-based mining bot for the Midnight Network's scavenger hunt, allowing users to automatically mine for NIGHT tokens with multiple wallets.

## Disclaimer

This is an unofficial tool, and has not been properly tested. Use it at your own risk. 

I will be updating and improving this software regularly. Please keep up to date by re-downloading from this repository and coppying over you `wallets.json` and `challenges.json` files, or simply by running `git pull`. 

## How It Works

The miner operates by performing the following steps:
1.  **Wallet Setup**: It creates or loads several Cardano wallets to be used for mining. These wallets are stored in `wallets.json`.
2.  **Registration**: The bot registers the wallets with the Midnight Scavenger Mine API and agrees to the terms and conditions.
3.  **Challenge Loop**: It continuously polls the API for new mining challenges. Challenges are stored in `challenges.json` so they can be resumed later.
4.  **Mining**: When a new challenge is received, the bot uses the provided parameters to build a large proof-of-work table (ROM). It then rapidly searches for a valid nonce that solves the challenge's difficulty requirement. The core hashing logic is performed by a WebAssembly module (`ashmaize_web_bg.wasm`) for performance.
5.  **Submission**: Once a solution is found, it is submitted to the API to earn NIGHT tokens.

## Prerequisites

Before running the miner, ensure you have the following:

1.  **Python 3**: The script is written in Python.
2.  **Required Libraries**: Install the necessary Python packages using pip:
    ```bash
    pip install wasmtime requests pycardano cbor2
    ```

## Usage

You can run the miner from your terminal.

-   **Start mining**:
    This command will either load an existing wallet from `wallets/wallet1.json` or guide you through creating a new one if it doesn't exist.
    ```bash
    python miner.py
    ```

-   **Multiple workers/wallets**:
    To mine with multiple wallets, use:
    ```bash
    python miner.py --workers <number of workers>
    ```
    Each worker typically uses one CPU core. For optimal performance, avoid running more workers than your CPU has cores.

    ```bash
    python main.py --wallet-file path/to/your_wallet.json
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

The dashboard displays important information about the status of each worker. The `Challenge` column shows which challenge ID the worker is trying to solve. It also shows statuses if not actively mining, for example "Waiting" if all known challenges have been completed. `Completed` shows how many solutions have been sucessfully submitted (and verified) by the server. `NIGHT` is an estimation of the rewards each wallet will receive. This is updated every 24 hours.

```
==============================================================================================================
                                    MIDNIGHT MULTI-WALLET MINER DASHBOARD                                     
==============================================================================================================
Active Workers: 6 | Last Update: 2025-11-03 19:22:11
==============================================================================================================

ID   Address                                      Challenge            Attempts   H/s      Completed  NIGHT     
--------------------------------------------------------------------------------------------------------------
0    addr1vxask5vpp8p4xddsc3qd63luy4ecf67233...   **D05C02             470,000    204      4          0         
1    addr1v43qjfemmksg5yjysevyndfqs7zpmad8yy...   **D05C19             471,000    204      8          7.043     
2    addr1v9hcpxeevkks7g4mvyls029yuvvsm0dfzl...   **D05C20             48,000     203      5          0         
3    addr1vx64c8703ketwnjtxkjcqzsktwkcvhve7f...   **D05C20             154,000    203      7          3.522     
4    addr1vxh3ckvkena0hzm24fhj9ac9ezrjz5ufju...   **D05C03             20,000     203      5          0         
5    addr1v8ugwtuwyqwh42ejd5af6f5tvzpjt4m5r2...   **D05C18             316,000    203      2          0         
--------------------------------------------------------------------------------------------------------------
TOTAL                                                                              1221     31         10.565    
==============================================================================================================

Press Ctrl+C to stop all miners
```

