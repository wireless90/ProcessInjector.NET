namespace ProcessInjector.Common
{
    public interface IRunPortableExecutable
    {
        bool Run(string targetProcessFileName, byte[] payload, string arguments);
    }
}
