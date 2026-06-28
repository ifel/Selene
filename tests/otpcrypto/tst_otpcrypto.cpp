#include <QtTest>

#include "utils/otpcrypto.h"

class TstOtpCrypto: public QObject {
  Q_OBJECT
private slots:
  // Locks the current algorithm: SHA-256(pin + salt + passphrase) uppercase hex.
  // Value computed independently (sha256sum) for these inputs. GREEN.
  void algorithmIsStable() {
    const QString h = OtpCrypto::generateOtpHash(
      "9067", "7e4f274a9a39bd8b3f36ef811d318076", "test");
    QCOMPARE(h, QStringLiteral(
      "104B19FE9C4E5100CC4A09FDAF4550A9DA6D746CAB598FBD6A66B5640757F368"));
  }

  void hashIsUppercaseHex64() {
    const QString h = OtpCrypto::generateOtpHash("1234", "abcd", "");
    QCOMPARE(h.length(), 64);
    QCOMPARE(h, h.toUpper());
    QVERIFY(QRegularExpression("^[0-9A-F]{64}$").match(h).hasMatch());
  }

  void differentInputsDifferentHash() {
    // Different content must hash differently.
    QVERIFY(OtpCrypto::generateOtpHash("1234", "ab", "x")
            != OtpCrypto::generateOtpHash("1234", "ab", "y"));
    QVERIFY(OtpCrypto::generateOtpHash("1111", "ab", "")
            != OtpCrypto::generateOtpHash("2222", "ab", ""));
  }

  // HIGH BAR — EXPECTED TO FAIL today. The server log for these exact inputs
  // expected hash 1DBFA68B..., but our client algorithm (plain string
  // concatenation, see algorithmIsStable above) produces 104B19FE...
  // i.e. the client OTP hash does NOT match what the server computed. The
  // salt is a 32-char hex string and is very likely meant to be hex-decoded to
  // 16 raw bytes before hashing. This red test documents that open
  // client/server OTP mismatch until it's reconciled.
  void matchesServerExpectedHash() {
    const QString h = OtpCrypto::generateOtpHash(
      "9067", "7e4f274a9a39bd8b3f36ef811d318076", "test");
    QCOMPARE(h, QStringLiteral(
      "1DBFA68BC208F14DEF7D6B9355CA49823E3EAED6B8A32B6E031A7AFB28D4F709"));
  }

  void pinValidation_data() {
    QTest::addColumn<QString>("pin");
    QTest::addColumn<bool>("valid");
    QTest::newRow("ok")        << "9067"  << true;
    QTest::newRow("zeros")     << "0000"  << true;
    QTest::newRow("too short") << "123"   << false;
    QTest::newRow("too long")  << "12345" << false;
    QTest::newRow("letters")   << "12a4"  << false;
    QTest::newRow("empty")     << ""      << false;
    QTest::newRow("space")     << "12 4"  << false;
  }
  void pinValidation() {
    QFETCH(QString, pin);
    QFETCH(bool, valid);
    QCOMPARE(OtpCrypto::validatePinFormat(pin), valid);
  }
};

QTEST_GUILESS_MAIN(TstOtpCrypto)
#include "tst_otpcrypto.moc"
