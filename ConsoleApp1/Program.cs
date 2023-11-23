using System;
using System.IO;
using System.Security.Cryptography;
using System.Net.Http;
using System.Text.Json;
using System.Reflection;

namespace ConsoleApp1
{
    class ConsoleApp1
    {
        class ScanDetails
        {
            public string? def_time { get; set; }
            public int scan_result_i { get; set; }
            public string? threat_found { get; set; }
        }

        string ActualFilename = "";
        string GlobalApiKey = "";

        (string Error, string StringHash) GetFileHash(string FilePath)
        {
            string Error = "";
            string StringHash = "";

            if (File.Exists(FilePath))
            {
                FileStream file = File.OpenRead(FilePath);

                SHA256 Sha256 = SHA256.Create();
                byte[] ByteHash = Sha256.ComputeHash(file);
                StringHash = BitConverter.ToString(ByteHash).Replace("-", "");

                ActualFilename = Path.GetFileName(FilePath);
            }
            else
            {
                Error = "File path is invalid.";
            }

            return (Error, StringHash);
        }

        async Task<(string error, string data_id)> UploadFile(string FilePath)
        {
            string error = "";
            string data_id = "";

            string url = "https://api.metadefender.com/v4/file";

            HttpClient ClientHttp = new();
            ClientHttp.DefaultRequestHeaders.Add("apikey", GlobalApiKey);
            var fileStream = File.OpenRead(FilePath);

            MultipartFormDataContent content = new()
            {
                {
                    new StreamContent(fileStream), "file", Path.GetFileName(FilePath)
                }
            };

            var response = await ClientHttp.PostAsync(url, content);
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadAsStreamAsync();

                var jsonDocument = JsonDocument.Parse(result);

                if (jsonDocument.RootElement.TryGetProperty("data_id", out JsonElement resultdata))
                {
                    data_id = resultdata.ToString();
                }
            }
            else
            {
                error = response.StatusCode.ToString();
            }

            return (error, data_id);
        }

        async Task CheckAHash(string FilePath, string HashingResult)
        {
            HttpClient ClientHttp = new();
            ClientHttp.DefaultRequestHeaders.Add("apikey", GlobalApiKey);

            string ApiUrl = $"https://api.metadefender.com/v4/hash/{HashingResult}";

            try
            {
                HttpResponseMessage HttpResponse = await ClientHttp.GetAsync(ApiUrl);
                if (HttpResponse.IsSuccessStatusCode)
                {
                    string result = await HttpResponse.Content.ReadAsStringAsync();

                    var jsonDocument = JsonDocument.Parse(result);

                    if (jsonDocument.RootElement.TryGetProperty("scan_results", out JsonElement scanResults))
                    {
                        scanResults.TryGetProperty("progress_percentage", out JsonElement ProgressPercentage);
                        if (ProgressPercentage.GetInt32() < 100)
                        {
                            Console.WriteLine($"Progress: {ProgressPercentage}%, waiting...");

                            await Task.Delay(10000);

                            await CheckAHash(FilePath, HashingResult);
                        }
                        else
                        {
                            Console.WriteLine($"Filename: {ActualFilename}");
                            scanResults.TryGetProperty("total_detected_avs", out JsonElement OverallResult);
                            Console.WriteLine($"OverallStatus: {(OverallResult.GetInt32() != 0 ? "Infected" : "Clean")}");

                            if (scanResults.TryGetProperty("scan_details", out JsonElement scanResults2))
                            {
                                var scan_details = JsonSerializer.Deserialize<Dictionary<string, ScanDetails>>(scanResults2);

                                if (scan_details != null)
                                {
                                    foreach (var element in scan_details)
                                    {
                                        Console.WriteLine($"Engine: {element.Key}");
                                        Console.WriteLine($"ThreatFound: {(element.Value.scan_result_i != 0 ? element.Value.threat_found : "Clean")}");
                                        Console.WriteLine($"ScanResult: {element.Value.scan_result_i}");
                                        Console.WriteLine($"DefTime: {element.Value.def_time}");

                                        Console.WriteLine();
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("Property 'scan_details' of 'scan_results' does not exist.");
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("Property 'scan_results' of 'Result' does not exist.");
                    }
                }
                else
                {
                    var (error, data_id) = await UploadFile(FilePath);

                    if (!string.IsNullOrEmpty(error))
                    {
                        Console.WriteLine($"Error: {error}");
                    }
                    else
                    {
                        Console.WriteLine("File was uploaded.");

                        await CheckADataId(FilePath, data_id);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        async Task CheckADataId(string FilePath, string data_id)
        {
            Console.WriteLine();

            HttpClient ClientHttp = new();
            ClientHttp.DefaultRequestHeaders.Add("apikey", GlobalApiKey);

            string ApiUrl = $"https://api.metadefender.com/v4/file/{data_id}";

            try
            {
                HttpResponseMessage HttpResponse = await ClientHttp.GetAsync(ApiUrl);
                if (HttpResponse.IsSuccessStatusCode)
                {
                    string result = await HttpResponse.Content.ReadAsStringAsync();

                    var jsonDocument = JsonDocument.Parse(result);

                    if (jsonDocument.RootElement.TryGetProperty("scan_results", out JsonElement scanResults))
                    {
                        scanResults.TryGetProperty("progress_percentage", out JsonElement ProgressPercentage);
                        if (ProgressPercentage.GetInt32() < 100)
                        {
                            Console.WriteLine($"Progress: {ProgressPercentage}%, waiting...");

                            await Task.Delay(10000);

                            await CheckADataId(FilePath, data_id);
                        }
                        else
                        {
                            Console.WriteLine($"Filename: {ActualFilename}");
                            scanResults.TryGetProperty("total_detected_avs", out JsonElement OverallResult);
                            Console.WriteLine($"OverallStatus: {(OverallResult.GetInt32() != 0 ? "Infected" : "Clean")}");

                            if (scanResults.TryGetProperty("scan_details", out JsonElement scanResults2))
                            {
                                var scan_details = JsonSerializer.Deserialize<Dictionary<string, ScanDetails>>(scanResults2);

                                if (scan_details != null)
                                {
                                    foreach (var element in scan_details)
                                    {
                                        Console.WriteLine($"Engine: {element.Key}");
                                        Console.WriteLine($"ThreatFound: {(element.Value.scan_result_i != 0 ? element.Value.threat_found : "Clean")}");
                                        Console.WriteLine($"ScanResult: {element.Value.scan_result_i}");
                                        Console.WriteLine($"DefTime: {element.Value.def_time}");

                                        Console.WriteLine();
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("Property 'scan_details' of 'scan_results' does not exist.");
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("Property 'scan_results' of 'Result' does not exist.");
                    }
                }
                else
                {
                    Console.WriteLine($"Error status code: {HttpResponse.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public async Task Program(string FilePath)
        {
            GlobalApiKey = "changeme";

            var (HashingError, HashingResult) = GetFileHash(FilePath);

            if (string.IsNullOrEmpty(HashingError))
            {
                await CheckAHash(FilePath, HashingResult);
            }
            else
            {
                Console.WriteLine(HashingError);
            }
        }

        static async Task Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Parameters error.");

                return;
            }

            string FileName = args[0];
            string ActualPath = AppContext.BaseDirectory;
            string FilePath = Path.Combine(ActualPath, FileName);

            ConsoleApp1 App = new();
            await App.Program(FilePath);
        }
    }
}