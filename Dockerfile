FROM scratch
COPY target/x86_64-unknown-linux-musl/release/rust_repo_template /
WORKDIR /
ENTRYPOINT [ "/rust_repo_template" ]
