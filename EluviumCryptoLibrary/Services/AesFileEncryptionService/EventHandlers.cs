namespace EluviumCore.Services.EncryptionService
{
    public class EventHandlers
    {
        public delegate void OnEncryptionMessageHandler(string message);

        public delegate void OnDecryptionMessageHandler(string message);

        public delegate void OnEncryptionProgressHandler(int percentageDone, string message);

        public delegate void OnDecryptionProgressHandler(int percentageDone, string message);

        public delegate void OnHashProgressHandler(int percentageDone, string message);
    }
}