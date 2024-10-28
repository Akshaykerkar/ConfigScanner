using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32; // Provides access to the Windows registry

namespace ConfigScanner
{
    class Program
    {
        static void Main(string[] args)
        {
            string auditFilePath = "CIS_Microsoft_Windows_11_Enterprise_v3.0.0_L1.audit";  // Path to the audit file
            string reportFilePath = "scan_results.txt"; // Path for the output report file

            // Parse the audit file and get the items to scan
            List<AuditItem> auditItems = ParseAuditFile(auditFilePath);
            
            // Perform the scan based on audit items
            List<ScanResult> scanResults = PerformScan(auditItems);

            // Generate a report based on scan results
            GenerateReport(scanResults, reportFilePath);
            Console.WriteLine($"Scan completed. Report saved to {reportFilePath}");
        }

        // Function to parse the audit file and extract configuration items
        static List<AuditItem> ParseAuditFile(string filePath)
        {
            var auditItems = new List<AuditItem>();
            string[] lines = File.ReadAllLines(filePath);
            AuditItem currentItem = null;

            foreach (string line in lines)
            {
                if (line.StartsWith("<custom_item>"))
                {
                    currentItem = new AuditItem();
                }
                else if (line.StartsWith("description") && currentItem != null)
                {
                    currentItem.Description = line.Split(':')[1].Trim();
                }
                else if (line.StartsWith("reg_key") && currentItem != null)
                {
                    currentItem.RegKey = line.Split(':')[1].Trim();
                }
                else if (line.StartsWith("reg_item") && currentItem != null)
                {
                    currentItem.RegItem = line.Split(':')[1].Trim();
                }
                else if (line.StartsWith("value_data") && currentItem != null)
                {
                    currentItem.ExpectedValue = line.Split(':')[1].Trim();
                }
                else if (line.StartsWith("</custom_item>") && currentItem != null)
                {
                    auditItems.Add(currentItem);
                    currentItem = null;
                }
            }

            return auditItems;
        }

        // Function to perform system scan based on audit items
        static List<ScanResult> PerformScan(List<AuditItem> auditItems)
        {
            var scanResults = new List<ScanResult>();

            foreach (var item in auditItems)
            {
                var result = new ScanResult
                {
                    Description = item.Description,
                    RegKey = item.RegKey,
                    RegItem = item.RegItem,
                    ExpectedValue = item.ExpectedValue
                };

                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(item.RegKey))
                    {
                        if (key != null)
                        {
                            object actualValue = key.GetValue(item.RegItem);
                            result.ActualValue = actualValue?.ToString();
                            result.Status = (result.ActualValue == result.ExpectedValue) ? "Compliant" : "Non-Compliant";
                        }
                        else
                        {
                            result.Status = "Registry Key Not Found";
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Status = $"Error: {ex.Message}";
                }

                scanResults.Add(result);
            }

            return scanResults;
        }

        // Function to generate a text report from the scan results
        static void GenerateReport(List<ScanResult> scanResults, string filePath)
        {
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine("System Configuration Scan Report");
                writer.WriteLine("===============================");
                foreach (var result in scanResults)
                {
                    writer.WriteLine($"Description: {result.Description}");
                    writer.WriteLine($"Registry Key: {result.RegKey}");
                    writer.WriteLine($"Registry Item: {result.RegItem}");
                    writer.WriteLine($"Expected Value: {result.ExpectedValue}");
                    writer.WriteLine($"Actual Value: {result.ActualValue}");
                    writer.WriteLine($"Status: {result.Status}");
                    writer.WriteLine();
                }
            }
        }
    }
}
