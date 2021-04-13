(function() {var implementors = {};
implementors["ecdsa"] = [{"text":"impl&lt;C&gt; <a class=\"trait\" href=\"signature/verifier/trait.Verifier.html\" title=\"trait signature::verifier::Verifier\">Verifier</a>&lt;<a class=\"struct\" href=\"ecdsa/struct.Signature.html\" title=\"struct ecdsa::Signature\">Signature</a>&lt;C&gt;&gt; for <a class=\"struct\" href=\"ecdsa/verify/struct.VerifyingKey.html\" title=\"struct ecdsa::verify::VerifyingKey\">VerifyingKey</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"ecdsa/trait.Curve.html\" title=\"trait ecdsa::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/point/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::point::ProjectiveArithmetic\">ProjectiveArithmetic</a> + <a class=\"trait\" href=\"ecdsa/hazmat/trait.DigestPrimitive.html\" title=\"trait ecdsa::hazmat::DigestPrimitive\">DigestPrimitive</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;C::<a class=\"type\" href=\"ecdsa/hazmat/trait.DigestPrimitive.html#associatedtype.Digest\" title=\"type ecdsa::hazmat::DigestPrimitive::Digest\">Digest</a>: <a class=\"trait\" href=\"digest/digest/trait.Digest.html\" title=\"trait digest::digest::Digest\">Digest</a>&lt;OutputSize = C::<a class=\"type\" href=\"elliptic_curve/trait.Curve.html#associatedtype.FieldSize\" title=\"type elliptic_curve::Curve::FieldSize\">FieldSize</a>&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"elliptic_curve/type.FieldBytes.html\" title=\"type elliptic_curve::FieldBytes\">FieldBytes</a>&lt;C&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"type\" href=\"elliptic_curve/scalar/type.Scalar.html\" title=\"type elliptic_curve::scalar::Scalar\">Scalar</a>&lt;C&gt;&gt; + for&lt;'r&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'r <a class=\"type\" href=\"elliptic_curve/scalar/type.Scalar.html\" title=\"type elliptic_curve::scalar::Scalar\">Scalar</a>&lt;C&gt;&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"elliptic_curve/scalar/type.Scalar.html\" title=\"type elliptic_curve::scalar::Scalar\">Scalar</a>&lt;C&gt;: <a class=\"trait\" href=\"ff/trait.PrimeField.html\" title=\"trait ff::PrimeField\">PrimeField</a>&lt;Repr = <a class=\"type\" href=\"elliptic_curve/type.FieldBytes.html\" title=\"type elliptic_curve::FieldBytes\">FieldBytes</a>&lt;C&gt;&gt; + <a class=\"trait\" href=\"elliptic_curve/trait.FromDigest.html\" title=\"trait elliptic_curve::FromDigest\">FromDigest</a>&lt;C&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"elliptic_curve/point/type.AffinePoint.html\" title=\"type elliptic_curve::point::AffinePoint\">AffinePoint</a>&lt;C&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"ecdsa/hazmat/trait.VerifyPrimitive.html\" title=\"trait ecdsa::hazmat::VerifyPrimitive\">VerifyPrimitive</a>&lt;C&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"elliptic_curve/point/type.ProjectivePoint.html\" title=\"type elliptic_curve::point::ProjectivePoint\">ProjectivePoint</a>&lt;C&gt;: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"type\" href=\"elliptic_curve/point/type.AffinePoint.html\" title=\"type elliptic_curve::point::AffinePoint\">AffinePoint</a>&lt;C&gt;&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"ecdsa/type.SignatureSize.html\" title=\"type ecdsa::SignatureSize\">SignatureSize</a>&lt;C&gt;: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;u8&gt;,&nbsp;</span>","synthetic":false,"types":["ecdsa::verify::VerifyingKey"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()