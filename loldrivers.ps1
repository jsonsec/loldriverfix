function Scan-LOLDrivers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$path
    )

    Add-Type -TypeDefinition @"
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.IO;
    using System.Text;
    public class FileHashScanner {
        public static string ComputeSha256(string path) {
            try {
                using (FileStream stream = File.OpenRead(path)) {
                    SHA256Managed sha = new SHA256Managed();
                    byte[] checksum = sha.ComputeHash(stream);
                    return BitConverter.ToString(checksum).Replace("-", String.Empty);
                }
            } catch (Exception) {
                return null;
            }
        }
        public static string GetAuthenticodeHash(string path) {
            try {
                X509Certificate2 cert = new X509Certificate2(path);
                return BitConverter.ToString(cert.GetCertHash()).Replace("-", String.Empty);
            } catch (Exception) {
                return null;
            }
        }
    }
"@

    Write-Host "Downloading drivers.json..."
    $driversJsonUrl = "https://www.loldrivers.io/api/drivers.json"
    $driversJsonContent = Invoke-WebRequest -Uri $driversJsonUrl
    $driverData = $driversJsonContent.Content | ConvertFrom-Json
    Write-Host "Download complete."

    Write-Host "Building correlation tables"
    $fileHashes = @{}
    $authenticodeHashes = @{}
    foreach ($driverInfo in $driverData) {
        foreach ($sample in $driverInfo.KnownVulnerableSamples) {
            'MD5 SHA1 SHA256'.Split() | ForEach-Object {
                $fileHashValue = $sample.$_
                if ($fileHashValue) {
                    $fileHashes[$fileHashValue] = $driverInfo
                }
                $authCodeHashValue = $sample.Authentihash.$_
                if ($authCodeHashValue) {
                    $authenticodeHashes[$authCodeHashValue] = $driverInfo
                }
            }
        }
    }
    Write-Host "Done building correlation tables"

    function Scan-Directory {
        param([string]$directory)

        try {
            Get-ChildItem -Path $directory -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                $_.FullName -notmatch "\\DriverData\\"
            } | ForEach-Object {
                $filePath = $_.FullName
                Write-Verbose "Computing hash for ${filePath}..."
                try {
                    $fileHash = [FileHashScanner]::ComputeSha256($filePath)
                    $fileAuthenticodeHash = [FileHashScanner]::GetAuthenticodeHash($filePath)

                    if ($fileHashes.ContainsKey($fileHash)) {
                        Write-Host "SHA256 hash match found: $filePath with hash $fileHash (matching $($fileHashes[$fileHash].Description))"
                    }
                    if ($fileAuthenticodeHash -and $authenticodeHashes.ContainsKey($fileAuthenticodeHash)) {
                        Write-Host "Authenticode hash match found: $filePath with hash $fileAuthenticodeHash (matches $($authenticodeHashes[$fileAuthenticodeHash].Description))"
                    }
                } catch {
                    Write-Verbose "Error processing file ${filePath}: $_"
                }
            }
        } catch {
            Write-Verbose "Error accessing ${directory}: $_"
        }
    }

    Write-Host "Starting scan..."
    Scan-Directory -directory $path
    Write-Host "Scan complete."
}
