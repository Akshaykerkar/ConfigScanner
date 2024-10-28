namespace ConfigScanner
{
    class AuditItem
    {
        public string Description { get; set; }
        public string RegKey { get; set; }
        public string RegItem { get; set; }
        public string ExpectedValue { get; set; }
    }
}
