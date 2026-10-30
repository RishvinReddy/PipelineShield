/**
 * PipelineShield Secure In-Memory ZIP Extractor.
 *
 * Implements pure in-memory extraction for ZIP archives using Node.js built-in
 * Buffer and zlib APIs.
 *
 * Security guarantees:
 * - Zero disk I/O (pure in-memory, eliminates Zip Slip vulnerabilities).
 * - Strict buffer boundary verification (guards against out-of-bounds reads).
 * - Maximum archive size and uncompressed size enforcement (guards against zip bombs / OOM).
 * - Sanitized entry matching (ignores directory traversal sequences in pathnames).
 */

import { inflateRawSync } from "node:zlib";

const EOCD_SIGNATURE = 0x06054b50; // PK\x05\x06
const CD_HEADER_SIGNATURE = 0x02014b50; // PK\x01\x02
const LOCAL_HEADER_SIGNATURE = 0x04034b50; // PK\x03\x04

const COMPRESSION_STORED = 0;
const COMPRESSION_DEFLATED = 8;

export interface ExtractedFile {
  fileName: string;
  content: string;
  uncompressedSize: number;
}

export interface ZipExtractorOptions {
  /** Maximum allowed size for the input ZIP buffer (default: 10MB). */
  maxArchiveSizeBytes?: number;
  /** Maximum allowed size for the extracted uncompressed entry (default: 5MB). */
  maxUncompressedSizeBytes?: number;
}

const DEFAULT_MAX_ARCHIVE_SIZE = 10 * 1024 * 1024; // 10 MB
const DEFAULT_MAX_UNCOMPRESSED_SIZE = 5 * 1024 * 1024; // 5 MB

/**
 * Locate the End of Central Directory (EOCD) record by scanning backwards from the end of buffer.
 */
function findEndOfCentralDirectory(buf: Buffer): number {
  // EOCD record is minimum 22 bytes, plus max comment length 65535 bytes
  const minOffset = Math.max(0, buf.length - 22 - 65535);
  for (let i = buf.length - 22; i >= minOffset; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIGNATURE) {
      return i;
    }
  }
  return -1;
}

/**
 * Search and extract a specific file from a ZIP archive buffer in memory.
 *
 * @param zipBuffer Binary buffer of the ZIP file.
 * @param targetFileName Name of file to extract (e.g. "security-summary.json" or "reports/security-summary.json").
 * @param options Security size limits.
 * @returns ExtractedFile record with uncompressed string content.
 */
export function extractFileFromZip(
  zipBuffer: Buffer,
  targetFileName: string,
  options?: ZipExtractorOptions
): ExtractedFile {
  const maxArchiveSize = options?.maxArchiveSizeBytes ?? DEFAULT_MAX_ARCHIVE_SIZE;
  const maxUncompressedSize = options?.maxUncompressedSizeBytes ?? DEFAULT_MAX_UNCOMPRESSED_SIZE;

  if (zipBuffer.length > maxArchiveSize) {
    throw new Error(
      `ZIP archive size (${zipBuffer.length} bytes) exceeds maximum allowed limit of ${maxArchiveSize} bytes.`
    );
  }

  if (zipBuffer.length < 22) {
    throw new Error("Invalid ZIP archive: buffer too small to contain a valid End of Central Directory record.");
  }

  const eocdOffset = findEndOfCentralDirectory(zipBuffer);
  if (eocdOffset === -1) {
    throw new Error("Invalid ZIP archive: End of Central Directory (EOCD) record not found.");
  }

  // Parse EOCD fields
  const totalEntries = zipBuffer.readUInt16LE(eocdOffset + 10);
  const cdSize = zipBuffer.readUInt32LE(eocdOffset + 12);
  const cdOffset = zipBuffer.readUInt32LE(eocdOffset + 16);

  if (cdOffset + cdSize > eocdOffset || cdOffset > zipBuffer.length) {
    throw new Error("Malformed ZIP archive: Central Directory offset out of bounds.");
  }

  const normalizedTarget = targetFileName.replace(/\\/g, "/").toLowerCase();
  const targetBaseName = normalizedTarget.split("/").pop() || normalizedTarget;

  let currentOffset = cdOffset;

  for (let i = 0; i < totalEntries; i++) {
    if (currentOffset + 46 > zipBuffer.length) {
      throw new Error("Malformed ZIP archive: Central directory entry truncated.");
    }

    const signature = zipBuffer.readUInt32LE(currentOffset);
    if (signature !== CD_HEADER_SIGNATURE) {
      throw new Error(`Malformed ZIP archive: Invalid Central Directory signature at offset ${currentOffset}.`);
    }

    const compressionMethod = zipBuffer.readUInt16LE(currentOffset + 10);
    const compressedSize = zipBuffer.readUInt32LE(currentOffset + 20);
    const uncompressedSize = zipBuffer.readUInt32LE(currentOffset + 24);
    const fileNameLength = zipBuffer.readUInt16LE(currentOffset + 28);
    const extraFieldLength = zipBuffer.readUInt16LE(currentOffset + 30);
    const commentLength = zipBuffer.readUInt16LE(currentOffset + 32);
    const localHeaderOffset = zipBuffer.readUInt32LE(currentOffset + 42);

    const nameOffset = currentOffset + 46;
    if (nameOffset + fileNameLength > zipBuffer.length) {
      throw new Error("Malformed ZIP archive: File name extends beyond buffer bounds.");
    }

    const rawFileName = zipBuffer.toString("utf8", nameOffset, nameOffset + fileNameLength);
    const normalizedName = rawFileName.replace(/\\/g, "/").toLowerCase();
    const entryBaseName = normalizedName.split("/").pop() || normalizedName;

    // Advance to next central directory record
    currentOffset += 46 + fileNameLength + extraFieldLength + commentLength;

    // Check if this entry matches the target
    const isExactMatch = normalizedName === normalizedTarget;
    const isBaseNameMatch = entryBaseName === targetBaseName;

    if (isExactMatch || isBaseNameMatch) {
      // Validate entry size against zip bomb protection limits
      if (uncompressedSize > maxUncompressedSize) {
        throw new Error(
          `Extracted file size (${uncompressedSize} bytes) exceeds maximum allowed uncompressed limit of ${maxUncompressedSize} bytes.`
        );
      }

      // Read local file header to locate compressed data payload
      if (localHeaderOffset + 30 > zipBuffer.length) {
        throw new Error("Malformed ZIP archive: Local file header offset out of bounds.");
      }

      const localSignature = zipBuffer.readUInt32LE(localHeaderOffset);
      if (localSignature !== LOCAL_HEADER_SIGNATURE) {
        throw new Error(`Malformed ZIP archive: Invalid local header signature at offset ${localHeaderOffset}.`);
      }

      const localNameLen = zipBuffer.readUInt16LE(localHeaderOffset + 26);
      const localExtraLen = zipBuffer.readUInt16LE(localHeaderOffset + 28);
      const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
      const dataEnd = dataStart + compressedSize;

      if (dataEnd > zipBuffer.length) {
        throw new Error("Malformed ZIP archive: Compressed data payload exceeds buffer bounds.");
      }

      const rawData = zipBuffer.subarray(dataStart, dataEnd);

      let decompressedBuffer: Buffer;

      if (compressionMethod === COMPRESSION_STORED) {
        decompressedBuffer = rawData;
      } else if (compressionMethod === COMPRESSION_DEFLATED) {
        try {
          decompressedBuffer = inflateRawSync(rawData, {
            maxOutputLength: maxUncompressedSize,
          });
        } catch (err) {
          throw new Error(`Failed to decompress ZIP entry '${rawFileName}': ${err instanceof Error ? err.message : String(err)}`);
        }
      } else {
        throw new Error(`Unsupported compression method ${compressionMethod} for entry '${rawFileName}'.`);
      }

      if (decompressedBuffer.length > maxUncompressedSize) {
        throw new Error(
          `Decompressed data size (${decompressedBuffer.length} bytes) exceeds limit of ${maxUncompressedSize} bytes.`
        );
      }

      return {
        fileName: rawFileName,
        content: decompressedBuffer.toString("utf8"),
        uncompressedSize: decompressedBuffer.length,
      };
    }
  }

  throw new Error(`File '${targetFileName}' not found in ZIP archive.`);
}
