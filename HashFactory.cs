using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace SignatureCraft
{
    /// <summary>
    /// Interface for computing hash values from various data sources.
    /// </summary>
    public interface IHashFactory
    {
        /// <summary>
        /// Computes the hash value of the specified character span.
        /// </summary>
        /// <param name="data">The character span containing the data to hash.</param>
        public void ComputeHash(ReadOnlySpan<char> data);

        /// <summary>
        /// Computes the hash value of the specified byte array.
        /// </summary>
        /// <param name="data">The byte array containing the data to hash.</param>
        public void ComputeHash(byte[] data);

        /// <summary>
        /// Computes the hash value of the data read from the provided stream.
        /// </summary>
        /// <param name="data">The stream containing the data to hash.</param>
        public void ComputeHash(Stream data);

        /// <summary>
        /// Computes the hash value of the data read from the provided file stream.
        /// </summary>
        /// <param name="data">The file stream containing the data to hash.</param>
        public void ComputeHash(FileStream data);

        /// <summary>
        /// Computes the hash value of the data read from the provided memory stream.
        /// </summary>
        /// <param name="data">The memory stream containing the data to hash.</param>
        public void ComputeHash(MemoryStream data);

        /// <summary>
        /// Computes the hash value of the file specified by the given file path.
        /// </summary>
        /// <param name="filePath">The path to the file from which to compute the hash.</param>
        /// <exception cref="FileNotFoundException">Thrown if the specified file does not exist.</exception>
        public void ComputeHashFromFile(string filePath);

    }

    /// <summary>
    /// Provides methods to compute hash values using SHA-512 algorithm.
    /// </summary>
    public class HashFactory : IHashFactory
    {
        #region Private Variables, Constants
        private static readonly SHA512 INSTANCE = SHA512.Create();
        private readonly byte[] PROJECT_SALT = Array.Empty<byte>();
        private readonly byte[] IV;
        private byte[] _resultBytes = Array.Empty<byte>();
        private string _result = string.Empty;
        private bool _success = false;
        #endregion Private Variables, Constants
        #region Public Properties

        /// <summary>
        /// Gets the hash result as a byte array.
        /// </summary>
        public byte[] ResultBytes { get { return _resultBytes; } }

        /// <summary>
        /// Gets the hash result as a hexadecimal string.
        /// </summary>
        public string Result { get { return _result; } }

        /// <summary>
        /// Gets a value indicating whether the operation succeeded.
        /// </summary>
        /// <returns>
        ///   <c>true</c> if the operation succeeded; otherwise, <c>false</c>.
        /// </returns>
        public bool Success { get { return _success; } }
        #endregion Public Properties
        #region Constructors

        /// <summary>
        /// Initializes a new instance of the HashFactory class with default settings.
        /// </summary>
        public HashFactory()
        {
            PROJECT_SALT = GetAssemblyInfo();
            IV = new byte[PROJECT_SALT.Length];
            for (int i = 0; i < PROJECT_SALT.Length; i++)
            {
                IV[i] = PROJECT_SALT[i];
            }
        }

        /// <summary>
        /// Initializes a new instance of the HashFactory class with a custom salt.
        /// </summary>
        /// <param name="salt">The custom salt as a character span.</param>
        public HashFactory(ReadOnlySpan<char> salt)
        {
            int iv_indice = 0;
            PROJECT_SALT = GetAssemblyInfo();
            if (salt == null || salt.Length == 0)
            {
                IV = new byte[PROJECT_SALT.Length];
            }
            else
            {
                byte[] salt_bytes = GetShaBytes(salt);
                IV = new byte[salt_bytes.Length + PROJECT_SALT.Length];

                for (int i = 0; i < salt_bytes.Length; i++)
                {
                    IV[iv_indice++] = salt_bytes[i];
                }
            }

            for (int i = 0; i < PROJECT_SALT.Length; i++)
            {
                IV[iv_indice++] = PROJECT_SALT[i];
            }

        }
        #endregion Constructors
        #region Helper Methods
        private byte[] GetAssemblyInfo()
        {
            var assembly = Assembly.GetExecutingAssembly();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(assembly.GetName().Name);
            return GetShaBytes(sb.ToString());
        }
        private static byte[] GetShaBytes(ReadOnlySpan<char> salt)
        {
            return INSTANCE.ComputeHash(Encoding.UTF8.GetBytes(salt.ToArray()));
        }
        private static byte[] Merge(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Array.Copy(a, result, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);

            return result;
        }
        private byte[] StreamToArray(Stream stream)
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                stream.CopyTo(memoryStream);
                return memoryStream.ToArray();
            }
        }
        private void ConvertToString()
        {
            StringBuilder sb = new StringBuilder();
            foreach (var b in _resultBytes)
            {
                sb.Append(b.ToString("x2"));
            }
            _result = sb.ToString();
        }
        #endregion Helper Methods
        #region Public Methods

        /// <summary>
        /// Computes the hash value of the specified character span.
        /// </summary>
        /// <param name="data">The character span containing the data to hash.</param>
        public void ComputeHash(ReadOnlySpan<char> data)
        {
            _resultBytes = INSTANCE.ComputeHash(Merge(IV, GetShaBytes(data)));
            ConvertToString();
            _success = true;
        }

        /// <summary>
        /// Computes the hash value of the specified byte array.
        /// </summary>
        /// <param name="data">The byte array containing the data to hash.</param>
        public void ComputeHash(byte[] data)
        {
            _resultBytes = INSTANCE.ComputeHash(Merge(IV, data));
            ConvertToString();
            _success = true;
        }

        /// <summary>
        /// Computes the hash value of the data read from the provided stream.
        /// </summary>
        /// <param name="data">The stream containing the data to hash.</param>
        public void ComputeHash(Stream data)
        {
            _resultBytes = INSTANCE.ComputeHash(Merge(IV, StreamToArray(data)));
            ConvertToString();
            _success = true;
        }

        /// <summary>
        /// Computes the hash value of the data read from the provided file stream.
        /// </summary>
        /// <param name="data">The file stream containing the data to hash.</param>
        public void ComputeHash(FileStream data)
        {
            _resultBytes = INSTANCE.ComputeHash(Merge(IV, StreamToArray(data)));
            ConvertToString();
            _success = true;
        }

        /// <summary>
        /// Computes the hash value of the data read from the provided memory stream.
        /// </summary>
        /// <param name="data">The memory stream containing the data to hash.</param>
        public void ComputeHash(MemoryStream data)
        {
            _resultBytes = INSTANCE.ComputeHash(Merge(IV, StreamToArray(data)));
            ConvertToString();
            _success = true;
        }

        /// <summary>
        /// Computes the hash value of the file specified by the given file path.
        /// </summary>
        /// <param name="filePath">The path to the file from which to compute the hash.</param>
        /// <exception cref="FileNotFoundException">Thrown if the specified file does not exist.</exception>
        public void ComputeHashFromFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException(filePath);
            }
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                ComputeHash(fs);
            }
        }
        #endregion Public Methods
    }
}
