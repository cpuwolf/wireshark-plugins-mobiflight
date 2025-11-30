# MobiFlight USB Protocol Dissector for Wireshark

A Wireshark Lua dissector for parsing MobiFlight USB serial protocol packets.

## Installation

### Method 1: Manual Installation

1. Copy the Lua files to the Wireshark plugins directory:
   ```
   C:\Users\<your username>\AppData\Roaming\Wireshark\plugins
   ```

2. Restart Wireshark to load the plugin

### Method 2: Using Current Directory

If the current directory is already the Wireshark plugins directory, the files are ready. Simply restart Wireshark.

## Usage

### Viewing Parsed Results

After installing the plugin, open a `.pcapng` file containing MobiFlight USB protocol packets. Wireshark will automatically parse the protocol fields.

### Filtering MobiFlight Packets

Use the following filter in the Wireshark filter bar:

```
_ws.col.protocol == "USB MF"
```

Or use the protocol name:

```
MobiFlight
```

## Sample Files

The project includes sample capture files in the `sample/` directory:
- `USB Mega Pro Plugin and plugout.pcapng` - Example of MobiFlight USB device plug/unplug

## Demo

![MobiFlight USB Protocol Parsing Demo](img/MF_USB_decode.gif)

## File Description

- `dissector.lua` - Main protocol dissector implementation
- `init.lua` - Wireshark Lua initialization configuration
- `README.md` - This documentation file

## Author

Wei Shuai <cpuwolf@gmail.com>  
Created: 2025-11-29