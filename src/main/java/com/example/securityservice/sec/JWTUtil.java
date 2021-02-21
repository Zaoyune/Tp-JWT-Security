package com.example.securityservice.sec;

public class JWTUtil {
    public static final String SECRET="mySecret1234";
    public static final String AUTH_HEADER="Authorization";
    public static final long EXPIRE_ACCESS_TOKEN=2*60*1000;
    public static final long EXPIRE_REFRESH_TOKEN=300*24*60*60*1000;
    public static final String PREFIX = "Bearer ";
}
