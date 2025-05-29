# SecureTransfer - Ngrok Transfer Guide

## Overview

This document provides guidance on using ngrok with SecureTransfer for reliable encrypted file transfers over the internet.

## What is ngrok?

Ngrok is a service that creates secure tunnels from public URLs to your local machine. It allows you to expose your local SecureTransfer application to the internet without port forwarding, fixed IPs, or DNS configuration.

## Understanding the Issues

When using ngrok to transfer encrypted files, you may encounter the following issues:

1. **Network Corruption**: Ngrok tunnels can occasionally introduce minor data corruption during transfers, which is especially problematic for encrypted data where a single byte error can render the entire file unreadable.

2. **Connection Stability**: Ngrok connections may be less stable than direct LAN connections, leading to transfer interruptions.

3. **Performance Limitations**: Standard transfer settings optimized for local networks may be suboptimal for ngrok tunnels.

## Best Practices for Ngrok Transfers

### 1. Optimal Settings

SecureTransfer now automatically detects ngrok connections and applies the following optimizations:

- **Chunk Size**: Uses smaller chunks (512KB instead of 1-2MB) to reduce the impact of transfer interruptions
- **Buffer Size**: Increases socket buffer sizes to 256KB for better stability
- **Timeouts**: Uses longer timeouts (30s instead of 10s) for ngrok operations
- **Retries**: Implements 5 retry attempts for decryption with intelligent repair mechanisms
- **Error Recovery**: Advanced file repair algorithms to fix common corruption patterns

### 2. Connection Recommendations

- **Avoid Large Files**: Try to keep files under 100MB when using ngrok
- **Stable Internet**: Both sender and receiver should have stable internet connections
- **Premium Ngrok**: Consider using a paid ngrok account for better reliability and performance

### 3. Troubleshooting

If you encounter "Decryption Failed" errors:

1. Try sending the file again with optimized settings enabled
2. Break large files into smaller parts before sending
3. Use a direct connection method if possible (e.g., local network or port forwarding)
4. Check that both parties have the latest version of SecureTransfer with ngrok fixes

## Technical Details

SecureTransfer implements several technical fixes for ngrok transfers:

1. **Enhanced Connection Stability**: 
   - Optimized socket buffer sizes
   - Extended timeouts for ngrok operations
   - Improved error handling

2. **Chunked File Transfer**:
   - Length-prefixed chunks for better framing
   - Checksum verification for each chunk
   - Improved connection reset handling

3. **Robust Decryption**:
   - Multiple retry attempts with different strategies
   - Automatic repair of common corruption patterns
   - Adaptive handling based on file characteristics
   - Backup creation before repair attempts
   - Specific fixes for ngrok-related corruption patterns
   - Intelligent RSA key handling to prevent decryption failures

## Testing

Two test scripts are available to validate the ngrok transfer fixes:

### Basic Testing

```bash
python test_ngrok_fixes.py
```

This checks that all the ngrok optimization functions are working correctly.

### Complete Transfer Testing

```bash
python test_complete_ngrok_transfer.py --size 10
```

This comprehensive test will:
1. Create a test file of the specified size (10MB in this example)
2. Encrypt the file with SecureTransfer's encryption
3. Start a local server and simulate a complete transfer
4. Apply the ngrok-specific decryption with retry mechanisms
5. Verify data integrity after the complete cycle
6. Test the corruption recovery by introducing simulated errors

You can also clean up test files after running:

```bash
python test_complete_ngrok_transfer.py --clean
```

## Limitations

While the ngrok transfer fixes greatly improve reliability, there are still limitations:

- Files over 100MB may still encounter issues
- Extremely unstable connections may cause failures
- Some types of corruption may not be recoverable

## Configuration

### Setting up ngrok

1. Open the SecureTransfer application.
2. Go to Settings.
3. Enter your ngrok authentication token in the "Ngrok Auth Token" field.
4. Enable the "Optimize for Ngrok" option.
5. Save the settings.

Alternatively, you can manually configure the settings in `securetransfer/data/settings.json`:

```json
{
  "ngrok_chunk_size": 524288,
  "ngrok_buffer_size": 262144,
  "ngrok_timeout": 30,
  "ngrok_max_retries": 5,
  "ngrok_optimized": true,
  "ngrok_authtoken": "your_token_here",
  "ngrok_region": "us"
}
```

## Recent Improvements

The latest version includes several critical fixes for improved reliability:

- **Enhanced Encryption Compatibility**: Better handling of encryption keys during transfers
- **Automatic Key Management**: RSA keys are now automatically loaded when needed
- **Robust Corruption Recovery**: Multiple repair strategies can fix common ngrok-related corruption patterns
- **Comprehensive Testing**: Full end-to-end transfer testing with simulated corruption

## Future Improvements

We are continuously working to improve ngrok transfer reliability:

- Implementing progressive chunk size reduction
- Adding full transfer resume capability
- Creating a dedicated relay mode for challenging network conditions
- Implementing end-to-end verification with checksums at multiple layers
- Implementing end-to-end verification with checksums at multiple layers
