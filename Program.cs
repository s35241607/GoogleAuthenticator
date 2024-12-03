
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

            // 模擬資料庫儲存用戶密鑰
            var userSecrets = new ConcurrentDictionary<string, byte[]>();

            // 1. 生成密鑰並返回 QR Code
            app.MapGet("/api/google-auth/generate", (string email) =>
            {
                // 生成隨機密鑰
                var secretKey = KeyGeneration.GenerateRandomKey(20); // 20 bytes 的密鑰
                string base32Secret = Base32Encoding.ToString(secretKey);

                // 儲存密鑰到模擬資料庫
                userSecrets[email] = secretKey;

                // 生成綁定 URI
                string serviceName = "LanOuO";
                string otpUri = $"otpauth://totp/{serviceName}:{email}?secret={base32Secret}&issuer={serviceName}";

                // 生成 QR Code 圖片
                using var qrGenerator = new QRCodeGenerator();
                var qrCodeData = qrGenerator.CreateQrCode(otpUri, QRCodeGenerator.ECCLevel.Q);
                var qrCode = new PngByteQRCode(qrCodeData);
                byte[] image = qrCode.GetGraphic(10);

                // 回傳 QR Code 圖片檔案
                return Results.File(image, "image/png");
            });

            // 2. 驗證用戶輸入的 OTP
            app.MapPost("/api/google-auth/validate", (string email, string otpCode) =>
            {
                if (!userSecrets.ContainsKey(email))
                {
                    return Results.BadRequest("用戶未綁定 Google Authenticator。");
                }

                var secretKey = userSecrets[email];
                var totp = new Totp(secretKey);

                bool isValid = totp.VerifyTotp(otpCode, out _);
                return isValid ? Results.Ok("驗證成功！") : Results.BadRequest("驗證失敗！");
            });

            app.Run();
        }
    }
}
