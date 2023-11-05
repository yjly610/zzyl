package com.zzyl.service;

import com.zzyl.dto.LoginDto;
import com.zzyl.vo.UserVo;

public interface LoginService {
    UserVo login(LoginDto loginDto);
}
