package com.albert.smartvpn.data

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface VpnProfileDao {

    @Query("SELECT * FROM vpn_profiles ORDER BY id DESC")
    fun getAllProfiles(): Flow<List<VpnProfile>>

    @Query("SELECT * FROM vpn_profiles WHERE isSelected = 1 LIMIT 1")
    suspend fun getSelectedProfile(): VpnProfile?

    @Query("SELECT * FROM vpn_profiles WHERE isSelected = 1 ORDER BY id DESC")
    suspend fun getSelectedProfiles(): List<VpnProfile>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertProfile(profile: VpnProfile): Long

    @Delete
    suspend fun deleteProfile(profile: VpnProfile)

    @Query("UPDATE vpn_profiles SET isSelected = 0")
    suspend fun clearSelection()

    @Query("UPDATE vpn_profiles SET isSelected = 0 WHERE isImported = 1")
    suspend fun unselectImportedProfiles()

    @Query("UPDATE vpn_profiles SET isSelected = :selected WHERE id = :id")
    suspend fun setProfileSelected(id: Int, selected: Boolean = true)

    suspend fun selectProfile(id: Int) {
        clearSelection()
        setProfileSelected(id, true)
    }

    suspend fun toggleProfileSelection(profile: VpnProfile) {
        if (profile.isImported) {
            // Imported files can only be ticked ONE at a time (never combined)
            clearSelection()
            setProfileSelected(profile.id, true)
        } else {
            // Manual files can be ticked individually OR ticked together in multi-select
            unselectImportedProfiles()
            val newState = !profile.isSelected
            setProfileSelected(profile.id, newState)
            // Ensure at least one profile remains selected if user unticked the last one
            if (!newState && getSelectedProfiles().isEmpty()) {
                setProfileSelected(profile.id, true)
            }
        }
    }
}
