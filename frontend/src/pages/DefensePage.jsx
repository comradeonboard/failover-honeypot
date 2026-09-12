import DefenseShield from '../components/DefenseShield'

export default function DefensePage({ defense, onBan, onUnban }) {
  return <DefenseShield defense={defense} onBan={onBan} onUnban={onUnban} />
}
