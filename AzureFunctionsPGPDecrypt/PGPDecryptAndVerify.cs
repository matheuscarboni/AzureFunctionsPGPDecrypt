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
    public static class PGPDecryptAndVerify
    {
        [FunctionName(nameof(PGPDecryptAndVerify))]
        public static async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req, ILogger log)
        {
            log.LogInformation($"C# HTTP trigger function {nameof(PGPDecryptAndVerify)} processed a request.");

            string privateKeyBase64 = Environment.GetEnvironmentVariable("pgp-private-key");
            string passPhrase = Environment.GetEnvironmentVariable("pgp-passphrase");
            string publicKeyVerifyBase64 = Environment.GetEnvironmentVariable("pgp-public-key-verify");

            if (string.IsNullOrEmpty(privateKeyBase64))
            {
                return new BadRequestObjectResult($"Please add a base64 encoded private key to an environment variable called pgp-private-key");
            }

            if (string.IsNullOrEmpty(publicKeyVerifyBase64))
            {
                return new BadRequestObjectResult($"Please add a base64 encoded public key to an environment variable called pgp-public-key-verify");
            }

            byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
            string privateKey = Encoding.UTF8.GetString(privateKeyBytes);

            byte[] publicKeyVerifyBytes = Convert.FromBase64String(publicKeyVerifyBase64);
            string publicKeyVerify = Encoding.UTF8.GetString(publicKeyVerifyBytes);

            // TODO:Move this to environment
            string connectionString;
            string inputContainerName;
            try{
                BlobContainerClient inputContainer = new BlobContainerClient(connectionString,inputContainerName);
                BlobClient blobClient = inputContainer.GetBlobClient("test.pgp");
                BlobDownloadStreamingResult ms = await blobClient.DownloadStreamingAsync();
               
                using(Stream inputStream = new MemoryStream()) {
                    ms.Content.CopyTo(inputStream);
                    inputStream.Seek(0, SeekOrigin.Begin);

                    Stream decryptedData = await DecryptAndVerifyAsync(inputStream, privateKey, publicKeyVerify, passPhrase);
                    BlobContainerClient outputBlobContainer = new BlobContainerClient(connectionString, inputContainerName);
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

        private static async Task<Stream> DecryptAndVerifyAsync(Stream inputStream, string privateKey, string publicKeyVerify, string passPhrase)
        {
            // TODO: move to env
            string pass;
            EncryptionKeys encryptionKeys = new EncryptionKeys(publicKeyVerify, privateKey, pass);

            using (PGP pgp = new PGP(encryptionKeys))
            {
                Stream outputStream = new MemoryStream();

                using (inputStream){
                    await pgp.DecryptStreamAndVerifyAsync(inputStream, outputStream);
                    outputStream.Seek(0, SeekOrigin.Begin);
                    return outputStream;
                }
            }
        }
    }
}
