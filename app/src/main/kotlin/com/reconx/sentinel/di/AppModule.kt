package com.reconx.sentinel.di

import android.content.Context
import androidx.room.Room
import com.reconx.sentinel.core.common.DefaultDispatchers
import com.reconx.sentinel.core.common.DispatcherProvider
import com.reconx.sentinel.core.storage.SentinelDatabase
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    @Provides @Singleton
    fun dispatchers(): DispatcherProvider = DefaultDispatchers

    @Provides @Singleton
    fun database(@ApplicationContext ctx: Context): SentinelDatabase =
        Room.databaseBuilder(ctx, SentinelDatabase::class.java, "sentinel.db")
            .fallbackToDestructiveMigration().build()

    @Provides @Singleton
    fun settings(@ApplicationContext ctx: Context): SettingsRepository = SettingsRepository(ctx)
}
