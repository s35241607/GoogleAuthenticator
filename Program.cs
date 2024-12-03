
using OtpNet;
using QRCoder;
using System.Collections.Concurrent;

namespace GoogleAuthenticator
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddAuthorization();

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();

            // ������Ʈw�x�s�Τ�K�_
            var userSecrets = new ConcurrentDictionary<string, byte[]>();

            // 1. �ͦ��K�_�ê�^ QR Code
            app.MapGet("/api/google-auth/generate", (string email) =>
            {
                // �ͦ��H���K�_
                var secretKey = KeyGeneration.GenerateRandomKey(20); // 20 bytes ���K�_
                string base32Secret = Base32Encoding.ToString(secretKey);

                // �x�s�K�_�������Ʈw
                userSecrets[email] = secretKey;

                // �ͦ��j�w URI
                string serviceName = "LanOuO";
                string otpUri = $"otpauth://totp/{serviceName}:{email}?secret={base32Secret}&issuer={serviceName}";

                // �ͦ� QR Code �Ϥ�
                using var qrGenerator = new QRCodeGenerator();
                var qrCodeData = qrGenerator.CreateQrCode(otpUri, QRCodeGenerator.ECCLevel.Q);
                var qrCode = new PngByteQRCode(qrCodeData);
                byte[] image = qrCode.GetGraphic(10);

                // �^�� QR Code �Ϥ��ɮ�
                return Results.File(image, "image/png");
            });

            // 2. ���ҥΤ��J�� OTP
            app.MapPost("/api/google-auth/validate", (string email, string otpCode) =>
            {
                if (!userSecrets.ContainsKey(email))
                {
                    return Results.BadRequest("�Τ᥼�j�w Google Authenticator�C");
                }

                var secretKey = userSecrets[email];
                var totp = new Totp(secretKey);

                bool isValid = totp.VerifyTotp(otpCode, out _);
                return isValid ? Results.Ok("���Ҧ��\�I") : Results.BadRequest("���ҥ��ѡI");
            });

            app.Run();
        }
    }
}
