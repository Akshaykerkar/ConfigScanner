namespace ConfigScanner
{
    class ScanResult
    {
        public string Description { get; set; }
        public string RegKey { get; set; }
        public string RegItem { get; set; }
        public string ExpectedValue { get; set; }
        public string ActualValue { get; set; }
        public string Status { get; set; }
    }
}
