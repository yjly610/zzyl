package com.zzyl.service.impl;

import cn.hutool.core.util.ObjectUtil;
import com.zzyl.exception.BaseException;
import com.zzyl.service.UserService;
import com.zzyl.vo.UserAuth;
import com.zzyl.vo.UserVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //调用Mapper查询用户
        UserVo userVo = userService.findUserVoForLogin(username);
        //if (ObjectUtil.isEmpty(userVo)) throw new BaseException("用户不存在");
        return new UserAuth(userVo);
    }
}
