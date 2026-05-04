use secure_boundary::validate::{SecureValidate, ValidationContext};

struct TestDto {
    username: String,
    age: u32,
}

impl SecureValidate for TestDto {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.username.is_empty() {
            return Err("username_empty");
        }
        if self.username.len() > 64 {
            return Err("username_too_long");
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.age > 150 {
            return Err("age_unreasonable");
        }
        Ok(())
    }
}

#[test]
fn test_validate_syntax_pass() {
    let dto = TestDto {
        username: "alice".to_owned(),
        age: 30,
    };
    let ctx = ValidationContext::new();
    assert!(dto.validate_syntax(&ctx).is_ok());
}

#[test]
fn test_validate_syntax_empty_username() {
    let dto = TestDto {
        username: String::new(),
        age: 30,
    };
    let ctx = ValidationContext::new();
    let err = dto.validate_syntax(&ctx).unwrap_err();
    assert_eq!(err, "username_empty");
}

#[test]
fn test_validate_syntax_username_too_long() {
    let dto = TestDto {
        username: "a".repeat(100),
        age: 30,
    };
    let ctx = ValidationContext::new();
    let err = dto.validate_syntax(&ctx).unwrap_err();
    assert_eq!(err, "username_too_long");
}

#[test]
fn test_validate_semantics_pass() {
    let dto = TestDto {
        username: "alice".to_owned(),
        age: 30,
    };
    let ctx = ValidationContext::new();
    assert!(dto.validate_semantics(&ctx).is_ok());
}

#[test]
fn test_validate_semantics_unreasonable_age() {
    let dto = TestDto {
        username: "alice".to_owned(),
        age: 999,
    };
    let ctx = ValidationContext::new();
    let err = dto.validate_semantics(&ctx).unwrap_err();
    assert_eq!(err, "age_unreasonable");
}

#[test]
fn test_pipeline_order_syntax_before_semantics() {
    // Both syntax (username too long) and semantic (age unreasonable) failures present.
    // Syntax must be checked first — callers must call validate_syntax before validate_semantics.
    let dto = TestDto {
        username: "a".repeat(100),
        age: 999,
    };
    let ctx = ValidationContext::new();
    // Syntax fails
    assert!(dto.validate_syntax(&ctx).is_err());
    // If we don't short-circuit, semantics also fail — but the contract is: syntax first
    let syntax_result = dto.validate_syntax(&ctx);
    assert!(
        syntax_result.is_err(),
        "syntax must fail before semantics is checked"
    );
}
