using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace HIPAA_Validator
{
    public class Program
    {
        static void Main(string[] args)
        {
           
            var validator = new EDI837Validator();

            string sampleEDI = @"ISA*00*          *00*          *ZZ*SUBMITTER_ID   *ZZ*RECEIVER_ID    *210101*1000*^*00501*000000001*0*P*:~
GS*HC*SENDER_CODE*RECEIVER_CODE*20210101*1000*1*X*005010X222A1~
ST*837*0001*005010X222A1~
BHT*0019*00*1*20210101*1000*CH~
NM1*41*2*SUBMITTER_NAME*****46*TIN~
PER*IC*CONTACT_NAME*TE*1234567890~
NM1*40*2*RECEIVER_NAME*****46*TIN~
HL*1**20*1~
NM1*85*2*BILLING_PROVIDER*****XX*NPI~
N3*123 MAIN ST~
N4*ANYTOWN*ST*12345~
REF*EI*123456789~
HL*2*1*22*0~
SBR*P*18*GROUP123*INSURANCE_COMPANY*****MB~
NM1*IL*1*DOE*JOHN****MI*123456789~
N3*456 OAK ST~
N4*HOMETOWN*ST*54321~
DMG*D8*19800101*M~
NM1*PR*2*INSURANCE_COMPANY*****PI*PAYERID~
CLM*CLAIM123*100.00***11:B:1*Y*A*Y*Y~
DTP*431*D8*20210101~
CAS*CO*1*10.00~
NM1*82*1*PROVIDER*JANE****XX*NPI123~
SV1*HC:99213*75.00*UN*1***1~
DTP*472*D8*20210101~
SE*25*0001~
GE*1*1~
IEA*1*000000001~";

            var result = validator.ValidateEDI837(sampleEDI);

            Console.WriteLine($"Validation Result: {(result.IsValid ? "PASSED" : "FAILED")}");
            Console.WriteLine($"Error Count: {result.Errors.Count}");

            if (result.Errors.Any())
            {
                Console.WriteLine("\nValidation Errors:");
                foreach (var error in result.Errors)
                    Console.WriteLine($"- {error}");
            }

            string filePath = @"C:\temp\edi_claim_output.txt";
            bool saved = validator.SaveEDIToFile(sampleEDI, filePath, includeValidationResults: true);

            Console.WriteLine(saved
                ? $"\nEDI claim saved to: {filePath}"
                : "\nFailed to save EDI claim file");
        }
    }

    public class EDI837Validator
    {
        private readonly Dictionary<string, SegmentValidator> _validators;

        public EDI837Validator()
        {
            _validators = new Dictionary<string, SegmentValidator>
            {
                { "ISA", new ISAValidator() },
                { "GS", new GSValidator() },
                { "ST", new STValidator() },
                { "BHT", new BHTValidator() },
                { "NM1", new NM1Validator() },
                { "CLM", new CLMValidator() },
                { "SV1", new SV1Validator() }
            };
        }

        public ValidationResult ValidateEDI837(string ediData)
        {
            var result = new ValidationResult();

            var segments = ParseSegments(ediData);

            foreach (var segment in segments)
            {
                if (_validators.TryGetValue(segment.Tag, out var validator))
                {
                    var errors = validator.Validate(segment);
                    if (errors.Any())
                        result.Errors.AddRange(errors.Select(e => $"{segment.Tag}: {e}"));
                }
            }

            result.IsValid = !result.Errors.Any();
            return result;
        }

        public bool SaveEDIToFile(string ediData, string filePath, bool includeValidationResults = false)
        {
            try
            {
                var sb = new StringBuilder();

                if (includeValidationResults)
                {
                    var result = ValidateEDI837(ediData);
                    sb.AppendLine($"Validation Status: {(result.IsValid ? "PASSED" : "FAILED")}");
                    if (result.Errors.Any())
                    {
                        sb.AppendLine("Validation Errors:");
                        foreach (var error in result.Errors)
                            sb.AppendLine($"- {error}");
                    }
                    sb.AppendLine();
                }

                sb.AppendLine("EDI Data:");
                sb.AppendLine(ediData);

                Directory.CreateDirectory(Path.GetDirectoryName(filePath));
                File.WriteAllText(filePath, sb.ToString());

                return true;
            }
            catch
            {
                return false;
            }
        }

        private List<EDISegment> ParseSegments(string ediData)
        {
            return ediData.Split('~')
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(segment =>
                {
                    var elements = segment.Split('*').ToList();
                    return new EDISegment
                    {
                        Tag = elements[0],
                        Elements = elements.Skip(1).ToList(),
                        RawData = segment
                    };
                }).ToList();
        }
    }

    public class EDISegment
    {
        public string Tag { get; set; }
        public List<string> Elements { get; set; } = new List<string>();
        public string RawData { get; set; }
    }

    public class ValidationResult
    {
        public bool IsValid { get; set; } = true;
        public List<string> Errors { get; set; } = new List<string>();
    }

    // ===== Segment Validators =====
    public abstract class SegmentValidator
    {
        public abstract List<string> Validate(EDISegment segment);
    }

    public class ISAValidator : SegmentValidator
    {
        public override List<string> Validate(EDISegment segment)
        {
            var errors = new List<string>();
            if (segment.Elements.Count < 16)
                errors.Add("ISA segment must have 16 elements");

            if (segment.Elements.Count > 11 && segment.Elements[11] != "^")
                errors.Add("ISA12 must be '^' (repetition separator)");

            return errors;
        }
    }

    public class GSValidator : SegmentValidator
    {
        public override List<string> Validate(EDISegment segment)
        {
            var errors = new List<string>();
            if (segment.Elements.Count < 8)
                errors.Add("GS segment must have 8 elements");

            if (segment.Elements.Count > 0 && segment.Elements[0] != "HC")
                errors.Add("GS01 must be 'HC' for healthcare claims");

            return errors;
        }
    }

    public class STValidator : SegmentValidator
    {
        public override List<string> Validate(EDISegment segment)
        {
            var errors = new List<string>();
            if (segment.Elements.Count < 2)
                errors.Add("ST segment must have at least 2 elements");

            if (segment.Elements.Count > 0 && segment.Elements[0] != "837")
                errors.Add("ST01 must be '837' for healthcare claims");

            return errors;
        }
    }

    public class BHTValidator : SegmentValidator
    {
        public override List<string> Validate(EDISegment segment)
        {
            var errors = new List<string>();
            if (segment.Elements.Count < 4)
                errors.Add("BHT segment must have at least 4 elements");
            return errors;
        }
    }

    public class NM1Validator : SegmentValidator
    {
        public override List<string> Validate(EDISegment segment)
        {
            var errors = new List<string>();
            if (segment.Elements.Count < 3)
                errors.Add("NM1 segment must have at least 3 elements");

            var validCodes = new[] { "41", "85", "87", "PE", "PR", "QC" };
            if (segment.Elements.Count > 0 && !validCodes.Contains(segment.Elements[0]))
                errors.Add($"NM101 '{segment.Elements[0]}' is not a valid entity identifier code");

            return errors;
        }
    }

    public class CLMValidator : SegmentValidator
    {
        public override List<string> Validate(EDISegment segment)
        {
            var errors = new List<string>();
            if (segment.Elements.Count < 5)
                errors.Add("CLM segment must have at least 5 elements");
            return errors;
        }
    }

    public class SV1Validator : SegmentValidator
    {
        public override List<string> Validate(EDISegment segment)
        {
            var errors = new List<string>();

            if (segment.Elements.Count < 3)
            {
                errors.Add("SV1 segment must have at least 3 elements");
                return errors;
            }

            if (string.IsNullOrWhiteSpace(segment.Elements[0]))
                errors.Add("SV101 (Procedure Code) is required");

            if (!decimal.TryParse(segment.Elements[1], out _))
                errors.Add("SV102 (Charge Amount) must be a valid decimal");

            return errors;
        }
    }
}
