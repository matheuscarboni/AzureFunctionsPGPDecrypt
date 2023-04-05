using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using PgpCore;
using System.Threading.Tasks;
using System;
using System.Text;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Azure.Storage;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace AzureFunctionsPGPDecrypt
{
    public static class PGPDecrypt
    {
        [FunctionName(nameof(PGPDecrypt))]
        public static async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req, ILogger log)
        {
            log.LogInformation($"C# HTTP trigger function {nameof(PGPDecrypt)} processed a request.");

            string privateKeyBase64 = Environment.GetEnvironmentVariable("pgp-private-key");
            string passPhrase = Environment.GetEnvironmentVariable("pgp-passphrase");

            if (string.IsNullOrEmpty(privateKeyBase64))
            {
                return new BadRequestObjectResult($"Please add a base64 encoded private key to an environment variable called pgp-private-key");
            }

            byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
            string privateKey = Encoding.UTF8.GetString(privateKeyBytes);

            // TODO: Move this to environment
            string connectionString;
            string inputContainerName;
            string outputContainerName;
            try{
                BlobContainerClient inputContainer = new BlobContainerClient(connectionString,inputContainerName);
                BlobClient blobClient = inputContainer.GetBlobClient("test.pgp");
                BlobDownloadStreamingResult ms = await blobClient.DownloadStreamingAsync();

                using(Stream inputStream = new MemoryStream()) {
                    ms.Content.CopyTo(inputStream);
                    inputStream.Seek(0, SeekOrigin.Begin);
                    Stream decryptedData = await DecryptAsync(inputStream, privateKey, passPhrase);
                    BlobContainerClient outputBlobContainer = new BlobContainerClient(connectionString, outputContainerName);
                    BlobClient outputBlobClient = outputBlobContainer.GetBlobClient("test.txt");
                    await outputBlobClient.UploadAsync(decryptedData, true);

                    return new OkObjectResult(decryptedData);
                }
            }
            catch (PgpException pgpException)
            {
                return new BadRequestObjectResult(pgpException.Message);
            }
        }

        private static async Task<Stream> DecryptAsync(Stream inputStream, string privateKey, string passPhrase)
        {
            // TODO: move to env
            string pass;
            EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, pass);

            using (PGP pgp = new PGP(encryptionKeys))
            {
                Stream outputStream = new MemoryStream();

                using (inputStream) {
                    await pgp.DecryptStreamAsync(inputStream, outputStream);
                    outputStream.Seek(0, SeekOrigin.Begin);
                    return outputStream;
                }
            }
        }
    }
}
